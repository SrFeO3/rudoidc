"""
OIDC Server Test Script
Tests the three main scenarios: M2M, Pure SPA (Public), and BFF (Confidential),
plus authorize-page rendering, logout revocation, and CORS policy.

Requires: pip install requests pytest pyyaml (stdlib only besides these)

Conformance notes (see work/oidc_verification.md for the S-ID mapping):
- Expected server config values below (lifetimes, audiences, user profile data)
  mirror conf/config.yaml. If that file changes, update the constants marked
  with "config:" accordingly.
- Token signatures ARE cryptographically verified against the live JWKS
  using the stdlib-only Ed25519 verifier at the bottom of this file
  (RFC 8032 Section 5.1.7).
"""

import pytest
import yaml
import requests
import secrets
import hashlib
import base64
import json
import os
import time
import urllib3
from urllib.parse import urlparse, parse_qs

# --- Helper Functions ---

def generate_pkce():
    code_verifier = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode('ascii').rstrip('=')
    return code_verifier, code_challenge

def decode_jwt_payload(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        payload_b64 = parts[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_json)
    except Exception:
        return None

def decode_jwt_header(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        header_b64 = parts[0]
        header_b64 += '=' * (-len(header_b64) % 4)
        header_json = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_json)
    except Exception:
        return None

def b64url_decode(data):
    data += '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)

# --- Configuration Loading ---

def load_test_config():
    config_path = os.path.join(os.path.dirname(__file__), "test_cases.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

CONFIG_DATA = load_test_config()
BASE_URL = CONFIG_DATA['config']['base_url']
ISSUER = CONFIG_DATA['config']['issuer']
TEST_CASES = CONFIG_DATA['test_cases']
VERIFY_SSL = CONFIG_DATA['config'].get('verify_ssl', True)
HOST_HEADER = CONFIG_DATA['config'].get('host_header')

# --- Expected server config values (config: mirror conf/config.yaml) ---
# Per-client token audiences and lifetimes.
EXPECTED_CLIENTS = {
    # config: clients.another-app (Public)
    "another-app": {
        "audience": "another-api",              # config: audience
        "access_token_lifetime": 10,            # config: access_token_lifetime_seconds
        "id_token_lifetime": 3600,              # config: id_token_lifetime_seconds
    },
    # config: clients.fruit-shop (Confidential)
    "fruit-shop": {
        "audience": "fruit-shop",               # config: audience
        "access_token_lifetime": 10,            # config: access_token_lifetime_seconds
        "id_token_lifetime": 3600,              # config: id_token_lifetime_seconds
    },
}
# config: users.* profile records (passwords are referenced per-case).
EXPECTED_USERS = {
    "suzuki": {"family_name": "Suzuki", "given_name": "Taro",
               "preferred_username": "taro.sato"},
    "tanaka": {"family_name": "Tanaka", "given_name": "Hanako",
               "preferred_username": "hana.yamada"},
}
# config: clients.*.default_scope (both clients use "openid").
DEFAULT_SCOPE = "openid"
# config: basic_auth_credentials.* -> client_id mapping.
M2M_CLIENT_MAP = {
    "service-account-1": "fruit-shop",
    "batch-job-runner": "fruit-shop",
    "another-app-service": "another-app",
}

# Setup Global Session
SESSION = requests.Session()
SESSION.verify = VERIFY_SSL
if HOST_HEADER:
    SESSION.headers.update({'Host': HOST_HEADER})

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Live JWKS cache (fetched once per test session) ---

_JWKS_CACHE = None

def get_jwks():
    global _JWKS_CACHE
    if _JWKS_CACHE is None:
        res = SESSION.get(f"{BASE_URL}/jwks.json")
        assert res.status_code == 200, f"JWKS fetch failed: {res.status_code}"
        _JWKS_CACHE = res.json()
    return _JWKS_CACHE

def get_jwks_key():
    keys = get_jwks().get('keys', [])
    assert len(keys) > 0, "JWKS: No keys found"
    return keys[0]

def assert_token_signature(token, what):
    """Cryptographically verify a JWT against the live JWKS (Ed25519)."""
    parts = token.split('.')
    assert len(parts) == 3, f"{what}: malformed JWT"
    key = get_jwks_key()
    header = decode_jwt_header(token)
    assert header is not None, f"{what}: undecodable header"
    assert header.get('kid') == key.get('kid'), \
        f"{what}: kid mismatch (token={header.get('kid')}, jwks={key.get('kid')})"
    signing_input = f"{parts[0]}.{parts[1]}".encode('ascii')
    sig = b64url_decode(parts[2])
    pub = b64url_decode(key['x'])
    assert ed25519_verify(signing_input, sig, pub), \
        f"{what}: Ed25519 signature verification failed"

# --- Shared assertion helpers for conformant behavior ---

def assert_id_token_claims(id_token, username, client_id, nonce, scope):
    """OIDC Core Section 2: required ID Token claims + profile gating (S-16/S-18)."""
    claims = decode_jwt_payload(id_token)
    assert claims is not None, "Failed to decode ID token payload"
    assert claims.get("iss") == ISSUER, \
        f"ID iss mismatch. Expected {ISSUER}, got {claims.get('iss')}"
    assert claims.get("sub") == username, \
        f"ID sub mismatch. Expected {username}, got {claims.get('sub')}"
    assert claims.get("aud") == client_id, \
        f"ID aud mismatch. Expected {client_id}, got {claims.get('aud')}"
    assert isinstance(claims.get("exp"), int) and isinstance(claims.get("iat"), int), \
        "ID exp/iat must be integer NumericDates"
    expected_lifetime = EXPECTED_CLIENTS[client_id]["id_token_lifetime"]
    assert claims["exp"] - claims["iat"] == expected_lifetime, \
        f"ID lifetime mismatch. Expected {expected_lifetime}, got {claims['exp'] - claims['iat']}"
    assert claims.get("nonce") == nonce, \
        f"Nonce mismatch. Expected {nonce}, got {claims.get('nonce')}"
    scopes = set(scope.split())
    if "profile" in scopes:
        expected = EXPECTED_USERS[username]
        assert claims.get("family_name") == expected["family_name"], "ID family_name mismatch"
        assert claims.get("given_name") == expected["given_name"], "ID given_name mismatch"
        assert claims.get("preferred_username") == expected["preferred_username"], \
            "ID preferred_username mismatch"
        assert claims.get("name") == f"{expected['given_name']} {expected['family_name']}", \
            "ID name mismatch"
    else:
        assert claims.get("name") == username, "ID name fallback mismatch"
        assert "family_name" not in claims, "ID must not carry profile claims without profile scope"
    return claims

def assert_access_token_claims(access_token, username, client_id, scope, expires_in):
    """Access Token claims issued by this server (S-18/S-24)."""
    claims = decode_jwt_payload(access_token)
    assert claims is not None, "Failed to decode access token payload"
    assert claims.get("iss") == ISSUER, "Access iss mismatch"
    assert claims.get("sub") == username, "Access sub mismatch"
    assert claims.get("aud") == EXPECTED_CLIENTS[client_id]["audience"], \
        f"Access aud mismatch. Expected {EXPECTED_CLIENTS[client_id]['audience']}, got {claims.get('aud')}"
    assert claims.get("cid") == client_id, "Access cid mismatch"
    assert set(claims.get("scp", [])) == set(scope.split()), \
        f"Access scp mismatch. Expected {sorted(scope.split())}, got {claims.get('scp')}"
    assert isinstance(claims.get("exp"), int) and isinstance(claims.get("iat"), int), \
        "Access exp/iat must be integer NumericDates"
    assert claims["exp"] - claims["iat"] == expires_in, \
        "Access lifetime must equal the expires_in of the same response"
    return claims

def assert_token_headers(id_token, access_token):
    for tok, what in ((id_token, "ID token"), (access_token, "access token")):
        header = decode_jwt_header(tok)
        assert header is not None, f"{what}: undecodable header"
        assert header.get('alg') == 'EdDSA', f"{what}: Expected alg=EdDSA, got {header.get('alg')}"
        assert header.get('typ') == 'JWT', f"{what}: Expected typ=JWT, got {header.get('typ')}"
        assert header.get('kid'), f"{what}: missing kid"
    assert_token_signature(id_token, "ID token")
    assert_token_signature(access_token, "access token")

# --- Test Scenarios ---

@pytest.mark.parametrize("case", TEST_CASES, ids=lambda c: c['id'])
def test_oidc_scenario(case):
    """
    Dispatcher test function that runs specific logic based on the case type.
    """
    test_type = case['type']
    if test_type == 'discovery':
        run_discovery(case)
    elif test_type == 'm2m':
        run_m2m(case)
    elif test_type == 'jwks':
        run_jwks(case)
    elif test_type == 'token_header':
        run_token_header_check(case)
    elif test_type == 'spa':
        run_auth_flow(case, is_public=True)
    elif test_type == 'bff':
        run_auth_flow(case, is_public=False)
    elif test_type == 'authorize':
        run_authorize(case)
    elif test_type == 'logout':
        run_logout(case)
    elif test_type == 'cors':
        run_cors(case)
    else:
        pytest.fail(f"Unknown test type: {test_type}")

def run_discovery(case):
    res = SESSION.get(f"{BASE_URL}/.well-known/openid-configuration")
    assert res.status_code == 200, f"Discovery endpoint returned {res.status_code}"
    data = res.json()
    # OIDC Discovery Section 3: REQUIRED metadata + our 8 published fields (S-09/S-31).
    assert data['issuer'] == ISSUER, f"Issuer mismatch. Expected {ISSUER}, got {data['issuer']}"
    assert not urlparse(ISSUER).query and not urlparse(ISSUER).fragment, \
        "Discovery: issuer must have no query or fragment"
    assert urlparse(ISSUER).scheme == "https", "Discovery: issuer must use https"
    assert data['authorization_endpoint'] == f"{ISSUER}/authorize", \
        "Discovery: authorization_endpoint mismatch"
    assert data['token_endpoint'] == f"{ISSUER}/api/token", \
        "Discovery: token_endpoint mismatch"
    assert data['userinfo_endpoint'] == f"{ISSUER}/api/userinfo", \
        "Discovery: userinfo_endpoint mismatch"
    assert data['jwks_uri'] == f"{ISSUER}/jwks.json", \
        "Discovery: jwks_uri mismatch"
    assert data['response_types_supported'] == ["code"], \
        "Discovery: only the code flow is supported"
    assert data['subject_types_supported'] == ["public"], \
        "Discovery: subject_types_supported mismatch"
    assert "EdDSA" in data['id_token_signing_alg_values_supported'], \
        "Discovery: EdDSA not in supported algs"

def run_jwks(case):
    res = SESSION.get(f"{BASE_URL}/jwks.json")
    assert res.status_code == 200, f"JWKS endpoint returned {res.status_code}"
    assert "86400" in res.headers.get("Cache-Control", ""), \
        f"JWKS: expected Cache-Control max-age=86400, got {res.headers.get('Cache-Control')!r}"
    data = res.json()
    keys = data.get('keys', [])
    assert len(keys) > 0, "JWKS: No keys found"

    key = keys[0]
    assert key['kty'] == 'OKP', f"JWKS: Expected kty=OKP, got {key.get('kty')}"
    assert key['crv'] == 'Ed25519', f"JWKS: Expected crv=Ed25519, got {key.get('crv')}"
    assert key['alg'] == 'EdDSA', f"JWKS: Expected alg=EdDSA, got {key.get('alg')}"
    assert key['use'] == 'sig', f"JWKS: Expected use=sig, got {key.get('use')}"
    assert key.get('kid'), "JWKS: missing kid"
    # RFC 8037 Section 2: 32-byte public key as base64url (43 chars unpadded).
    assert len(key.get('x', '')) == 43, \
        f"JWKS: malformed x parameter: {key.get('x')!r}"
    assert len(b64url_decode(key['x'])) == 32, "JWKS: x must decode to 32 bytes"
    assert 'd' not in key, "JWKS: must not contain private key material"

def run_token_header_check(case):
    # Use M2M flow to quickly get a token
    username = "service-account-1"
    password = "secret-for-sa1"

    res = SESSION.post(
        f"{BASE_URL}/api/token",
        auth=(username, password),
        data={
            "grant_type": "client_credentials",
            "scope": "openid"
        }
    )
    assert res.status_code == 200, "Failed to get token for header check"
    data = res.json()
    access_token = data.get('access_token')
    assert access_token, "No access token returned"

    header = decode_jwt_header(access_token)
    assert header is not None, "Failed to decode token header"
    assert header.get('alg') == 'EdDSA', f"Token Header: Expected alg=EdDSA, got {header.get('alg')}"
    assert header.get('typ') == 'JWT', f"Token Header: Expected typ=JWT, got {header.get('typ')}"
    # The token must verify against the published JWKS key (S-18/S-19).
    assert_token_signature(access_token, "access token")

def run_m2m(case):
    # Configuration & Defaults
    username = case['username']
    password = case['password']
    grant_type = case.get('grant_type', 'client_credentials')

    exp_status = case.get('expected_status', 200)

    post_data = {"grant_type": grant_type}
    if not case.get('omit_scope'):
        post_data["scope"] = case.get('scope', 'openid')
    effective_scope = case.get('scope', DEFAULT_SCOPE) if not case.get('omit_scope') else DEFAULT_SCOPE

    res = SESSION.post(
        f"{BASE_URL}/api/token",
        auth=(username, password),
        data=post_data
    )
    assert res.status_code == exp_status, f"M2M token request status mismatch. Expected {exp_status}, got {res.status_code}. Body: {res.text}"

    if exp_status == 200:
        data = res.json()
        assert "access_token" in data, "Response missing access_token"
        # Client Credentials issues no ID Token (S-03: user-less grant).
        assert "id_token" not in data, "M2M response must not contain an id_token"
        assert data.get("token_type") == "Bearer", "M2M token_type must be Bearer"
        assert data.get("scope") == effective_scope, \
            f"M2M scope echo mismatch. Expected {effective_scope!r}, got {data.get('scope')!r}"
        assert data.get("expires_in") == EXPECTED_CLIENTS[M2M_CLIENT_MAP[username]]["access_token_lifetime"], \
            "M2M expires_in must equal the client access lifetime"
        claims = decode_jwt_payload(data["access_token"])
        assert claims is not None, "Failed to decode M2M access token"
        assert claims.get("sub") == username, "M2M access sub must be the service account"
        assert claims.get("cid") == M2M_CLIENT_MAP[username], "M2M access cid mismatch"
        assert set(claims.get("scp", [])) == set(effective_scope.split()), "M2M access scp mismatch"
        assert_token_signature(data["access_token"], "M2M access token")

def do_login(client_id, redirect_uri, username, password, scope=None, nonce=None,
             state="test_state_val", code_challenge=None, code_challenge_method="S256",
             omit_nonce=False, omit_redirect_uri=False, wrong_redirect_uri=False,
             omit_client_id=False, wrong_client_id=False, omit_scope=False,
             omit_state=False, response_type="code"):
    """POST /login with authorize-equivalent query params. Returns the response."""
    params = {
        "client_id": client_id,
        "response_type": response_type,
        "redirect_uri": redirect_uri,
        "scope": DEFAULT_SCOPE if scope is None else scope,
        "nonce": nonce or secrets.token_urlsafe(16),
        "state": state,
    }
    if omit_state:
        del params['state']
    if omit_scope:
        del params['scope']
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method
    if omit_nonce: del params['nonce']
    if omit_redirect_uri: del params['redirect_uri']
    if wrong_redirect_uri: params['redirect_uri'] = "http://evil.com/callback"
    if omit_client_id: del params['client_id']
    if wrong_client_id: params['client_id'] = "wrong-client"
    return SESSION.post(
        f"{BASE_URL}/login",
        params=params,
        data={"username": username, "password": password},
        allow_redirects=False
    ), params.get('nonce'), params.get('state')

def run_auth_flow(case, is_public):
    # --- Configuration & Defaults ---
    client_id = case['client_id']
    redirect_uri = case['redirect_uri']
    username = case['username']
    password = case['password']

    # Flags
    use_pkce = case.get('use_pkce', is_public) # Default: True for SPA, False for BFF
    pkce_method = case.get('pkce_method', 'S256')

    # Expected Outcomes
    exp_login_status = case.get('expected_login_status', 303)
    exp_token_status = case.get('expected_token_status', 200)

    # --- Step 1: Prepare Login (Authorize) ---
    nonce = secrets.token_urlsafe(16)
    state = "test_state_val"
    verifier, challenge = generate_pkce() if use_pkce else (None, None)

    login_kwargs = dict(
        scope=case.get('scope', 'openid'),
        nonce=nonce,
        state=state,
        omit_nonce=bool(case.get('omit_nonce')),
        omit_redirect_uri=bool(case.get('omit_redirect_uri')),
        wrong_redirect_uri=bool(case.get('wrong_redirect_uri')),
        omit_client_id=bool(case.get('omit_client_id_login')),
        wrong_client_id=bool(case.get('wrong_client_id_login')),
        omit_scope=bool(case.get('omit_scope')),
        omit_state=bool(case.get('omit_state')),
        response_type=case.get('response_type', 'code'),
    )
    if use_pkce:
        login_kwargs["code_challenge"] = challenge
        login_kwargs["code_challenge_method"] = pkce_method

    # Execute Login
    res, _, _ = do_login(client_id, redirect_uri, username, password, **login_kwargs)

    assert res.status_code == exp_login_status, f"Login status mismatch. Expected {exp_login_status}, got {res.status_code}. Body: {res.text}"

    if exp_login_status != 303:
        return # Stop if we expected login to fail

    # Effective scope: server falls back to the client default when omitted (S-17).
    effective_scope = case.get('scope', DEFAULT_SCOPE) if not case.get('omit_scope') else DEFAULT_SCOPE

    location = res.headers['Location']
    qs = parse_qs(urlparse(location).query)
    assert 'code' in qs, "Authorization code not found in redirect URL"
    code = qs['code'][0]
    if case.get('expect_no_state'):
        # An omitted state must stay absent, not become an empty `state=` (G-14).
        assert 'state' not in qs, f"State must be absent, got {qs.get('state')!r}"
    else:
        # The server must echo the state for CSRF protection (S-26).
        assert qs.get('state', [None])[0] == state, \
            f"State echo mismatch. Expected {state!r}, got {qs.get('state')!r}"

    # Optional: let the code expire before exchanging (S-22 lifetime).
    if case.get('sleep_before_exchange'):
        time.sleep(case['sleep_before_exchange'])

    # --- Step 2: Token Exchange ---
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }

    # Client Auth
    auth = None
    if is_public:
        token_data["client_id"] = client_id
    elif case.get('secret_in_body'):
        # client_secret_post (OIDC Core Section 9) as alternative to Basic.
        token_data["client_id"] = client_id
        token_data["client_secret"] = case.get('client_secret', '')
    else:
        # Confidential client uses Basic Auth
        secret = case.get('client_secret', '')
        if case.get('wrong_client_secret'): secret = "wrong-secret"

        if not case.get('omit_client_secret'):
            auth = (client_id, secret)
        else:
            # If omitting secret for BFF, we might still need client_id in body to identify client,
            # but usually Basic Auth provides both. If omitted, we send client_id in body to trigger 401 instead of 400/500
            token_data["client_id"] = client_id

    # PKCE Verifier
    if use_pkce:
        if not case.get('omit_code_verifier'):
            token_data["code_verifier"] = verifier
        if case.get('wrong_code_verifier'):
            token_data["code_verifier"] = "wrong_verifier_string"

    # Apply Token Overrides
    if case.get('invalid_code'): token_data['code'] = "invalid_auth_code"
    if case.get('wrong_client_id_token'):
        if is_public: token_data['client_id'] = "wrong-client"
        else: auth = ("wrong-client", case.get('client_secret', ''))

    # Execute Token Exchange
    def do_exchange():
        if case.get('garbage_bearer_header'):
            # Unrelated Authorization header: must not block client_secret_post (G-13).
            return SESSION.post(f"{BASE_URL}/api/token", data=token_data,
                                headers={"Authorization": "Bearer garbage-token"})
        return SESSION.post(f"{BASE_URL}/api/token", data=token_data, auth=auth)

    res = do_exchange()
    assert res.status_code == exp_token_status, f"Token exchange status mismatch. Expected {exp_token_status}, got {res.status_code}. Body: {res.text}"

    if exp_token_status != 200:
        return # Stop if we expected token exchange to fail

    data = res.json()
    assert data.get("token_type") == "Bearer", "token_type must be Bearer"
    assert "id_token" in data, "id_token missing from response"
    assert "access_token" in data, "access_token missing from response"
    assert isinstance(data.get("expires_in"), int), "expires_in must be an integer"

    # Refresh Tokens are issued only for the offline_access scope (S-06/S-23).
    if "offline_access" in effective_scope.split():
        assert data.get("refresh_token"), "refresh_token must be issued for offline_access scope"
    else:
        assert "refresh_token" not in data, \
            "refresh_token must not be issued without offline_access scope"

    # Token headers + cryptographic signatures (S-18/S-19).
    assert_token_headers(data["id_token"], data["access_token"])
    # Required ID claims, lifetime, nonce passthrough, profile gating (S-16/S-18).
    assert_id_token_claims(data["id_token"], username, client_id, nonce, effective_scope)
    # Access claims incl. lifetime consistency with expires_in (S-18/S-24).
    assert_access_token_claims(data["access_token"], username, client_id,
                               effective_scope, data["expires_in"])

    # --- Optional: UserInfo Endpoint Test ---
    if case.get('test_userinfo'):
        access_token = data.get('access_token')
        assert access_token, "Access token missing, cannot test userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        res_userinfo = SESSION.get(f"{BASE_URL}/api/userinfo", headers=headers)
        assert res_userinfo.status_code == 200, f"UserInfo request failed: {res_userinfo.text}"
        userinfo_data = res_userinfo.json()
        assert userinfo_data.get('sub') == username, f"UserInfo 'sub' mismatch. Expected {username}, got {userinfo_data.get('sub')}"
        # Profile claims follow the requested scope (S-17/C-5).
        if "profile" in effective_scope.split():
            expected = EXPECTED_USERS[username]
            assert userinfo_data.get('family_name') == expected['family_name'], \
                "UserInfo family_name mismatch"
            assert userinfo_data.get('given_name') == expected['given_name'], \
                "UserInfo given_name mismatch"
            assert userinfo_data.get('preferred_username') == expected['preferred_username'], \
                "UserInfo preferred_username mismatch"

    # --- Optional: Expired Access Token Test ---
    if case.get('test_expired_token'):
        access_token = data.get('access_token')
        assert access_token, "Access token missing, cannot test expiration"
        # Wait for the token to expire (lifetime is 10s in config)
        time.sleep(16)
        headers = {"Authorization": f"Bearer {access_token}"}
        res_expired = SESSION.get(f"{BASE_URL}/api/userinfo", headers=headers)
        assert res_expired.status_code == 401, f"Expired token should be rejected with 401, but got {res_expired.status_code}"

    # --- Optional: Replay Attack Test ---
    if case.get('replay_code'):
        res_replay = do_exchange()
        assert res_replay.status_code == 400, f"Replay attack should fail with 400, got {res_replay.status_code}"

    # --- Optional: Tampered Access Token Test ---
    if case.get('test_tampered_token'):
        access_token = data.get('access_token')
        assert access_token, "Access token missing, cannot test tampering"
        # Tamper with the signature (the last part of the JWT)
        parts = access_token.split('.')
        if len(parts) == 3:
            parts[2] = "tampered_signature"
            tampered_token = ".".join(parts)
            headers = {"Authorization": f"Bearer {tampered_token}"}
            res_tampered = SESSION.get(f"{BASE_URL}/api/userinfo", headers=headers)
            assert res_tampered.status_code == 401, f"Tampered token should be rejected with 401, but got {res_tampered.status_code}"
            # The tampered token must also fail local signature verification (C4 control).
            assert ed25519_verify(
                f"{parts[0]}.{parts[1]}".encode('ascii'),
                b64url_decode(parts[2]),
                b64url_decode(get_jwks_key()['x'])
            ) is False, "Tampered token must not verify"

    # --- Optional: Refresh Token Test ---
    if case.get('test_refresh'):
        refresh_token = data.get('refresh_token')
        assert refresh_token, "Refresh token missing in response"

        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }

        # Prepare auth/data for the refresh request
        refresh_auth = auth
        if is_public:
            # Public clients MUST send client_id in the body for refresh, unless we are testing the omission.
            if not case.get('omit_client_id_refresh'):
                refresh_data['client_id'] = client_id

        if case.get('invalid_refresh'): refresh_data['refresh_token'] = "invalid_refresh_token"

        if case.get('wrong_client_refresh'):
            if is_public:
                # For SPA, send the wrong client_id in the body
                refresh_data['client_id'] = "wrong-client"
            else:
                # For BFF, send the wrong client_id in Basic Auth
                refresh_auth = ("wrong-client", case.get('client_secret', ''))

        # Execute Refresh request
        res_refresh = SESSION.post(f"{BASE_URL}/api/token", data=refresh_data, auth=refresh_auth)

        # Assert based on expected status for the refresh action
        expected_refresh_status = case.get('expected_refresh_status', 200)
        assert res_refresh.status_code == expected_refresh_status, \
            f"Refresh status mismatch. Expected {expected_refresh_status}, got {res_refresh.status_code}. Body: {res_refresh.text}"

        if expected_refresh_status == 200:
            refresh_body = res_refresh.json()
            assert "access_token" in refresh_body, "New access token missing in refresh response"
            assert "id_token" in refresh_body, "New id_token missing in refresh response"
            assert_token_signature(refresh_body["access_token"], "refreshed access token")
            assert_token_signature(refresh_body["id_token"], "refreshed ID token")

def run_authorize(case):
    """GET /authorize page rendering (S-04/S-05: login page entry point)."""
    params = {
        "client_id": case.get('client_id', 'another-app'),
        "response_type": case.get('response_type', 'code'),
        "redirect_uri": case.get('redirect_uri', 'http://sample.another.example.com:9090/callback'),
        "scope": "openid",
        "nonce": secrets.token_urlsafe(16),
        "state": "test_state_val",
    }
    if case.get('omit_client_id'): del params['client_id']
    if case.get('unknown_client'): params['client_id'] = "wrong-client"
    if case.get('omit_redirect_uri'): del params['redirect_uri']
    if case.get('wrong_redirect_uri'): params['redirect_uri'] = "http://evil.com/callback"
    if case.get('omit_nonce'): del params['nonce']

    exp_status = case.get('expected_status', 200)
    res = SESSION.get(f"{BASE_URL}/authorize", params=params)
    assert res.status_code == exp_status, \
        f"Authorize status mismatch. Expected {exp_status}, got {res.status_code}. Body: {res.text[:200]}"
    if exp_status == 200:
        # The login form must repost to /login preserving the query string (S-04).
        assert "<form" in res.text and 'action="/login?' in res.text, \
            "Authorize page must render the login form posting to /login"

def do_full_code_flow(client_id, redirect_uri, username, password, scope,
                      use_pkce=True, auth=None, client_id_body=None):
    """Helper for logout tests: login -> code -> tokens. Returns token response JSON."""
    verifier, challenge = generate_pkce() if use_pkce else (None, None)
    nonce = secrets.token_urlsafe(16)
    kwargs = dict(scope=scope, nonce=nonce, code_challenge=challenge,
                  code_challenge_method="S256") if use_pkce else dict(scope=scope, nonce=nonce)
    res, _, _ = do_login(client_id, redirect_uri, username, password, **kwargs)
    assert res.status_code == 303, f"Setup login failed: {res.status_code} {res.text[:200]}"
    code = parse_qs(urlparse(res.headers['Location']).query)['code'][0]
    token_data = {"grant_type": "authorization_code", "code": code,
                  "redirect_uri": redirect_uri}
    if client_id_body:
        token_data["client_id"] = client_id_body
    if use_pkce:
        token_data["code_verifier"] = verifier
    res_tok = SESSION.post(f"{BASE_URL}/api/token", data=token_data, auth=auth)
    assert res_tok.status_code == 200, f"Setup token exchange failed: {res_tok.text[:200]}"
    return res_tok.json()

def run_logout(case):
    """POST /api/logout revocation semantics (S-23/S-28: proprietary revocation)."""
    scenario = case.get('scenario')

    if scenario == 'no_auth':
        # No token (or garbage): nothing to revoke, must not fail.
        res = SESSION.post(f"{BASE_URL}/api/logout")
        assert res.status_code == 204, f"Logout without token must be 204, got {res.status_code}"
        res = SESSION.post(f"{BASE_URL}/api/logout",
                           headers={"Authorization": "Bearer garbage.token.value"})
        assert res.status_code == 204, f"Logout with invalid token must be 204, got {res.status_code}"
        return

    if scenario == 'isolation':
        # Two users on the same client: revoking one must not affect the other.
        client_id = case['client_id']
        redirect_uri = case['redirect_uri']
        scope = case.get('scope', 'openid offline_access')
        tok_a = do_full_code_flow(client_id, redirect_uri, case['user_a'], case['pass_a'],
                                  scope, client_id_body=client_id)
        tok_b = do_full_code_flow(client_id, redirect_uri, case['user_b'], case['pass_b'],
                                  scope, client_id_body=client_id)
        res = SESSION.post(f"{BASE_URL}/api/logout",
                           headers={"Authorization": f"Bearer {tok_a['access_token']}"})
        assert res.status_code == 204, f"Logout must be 204, got {res.status_code}"
        res_a = SESSION.post(f"{BASE_URL}/api/token",
                             data={"grant_type": "refresh_token",
                                   "refresh_token": tok_a['refresh_token'],
                                   "client_id": client_id})
        assert res_a.status_code == 400, "Revoked refresh token (user A) must fail"
        res_b = SESSION.post(f"{BASE_URL}/api/token",
                             data={"grant_type": "refresh_token",
                                   "refresh_token": tok_b['refresh_token'],
                                   "client_id": client_id})
        assert res_b.status_code == 200, "Other user's refresh token must still work"
        return

    # Single-session revocation scenarios.
    is_public = case.get('client_type', 'spa') == 'spa'
    client_id = case['client_id']
    redirect_uri = case['redirect_uri']
    scope = case.get('scope', 'openid offline_access')
    if is_public:
        tokens = do_full_code_flow(client_id, redirect_uri, case['username'],
                                   case['password'], scope, client_id_body=client_id)
    else:
        secret = case['client_secret']
        tokens = do_full_code_flow(client_id, redirect_uri, case['username'],
                                   case['password'], scope, use_pkce=False,
                                   auth=(client_id, secret))
    assert tokens.get("refresh_token"), "Setup needs a refresh token (use offline_access scope)"

    if scenario == 'expired_access':
        # Even with an expired access token, logout must still revoke (exp ignored).
        time.sleep(EXPECTED_CLIENTS[client_id]["access_token_lifetime"] + 2)
    elif scenario not in ('revoke',):
        pytest.fail(f"Unknown logout scenario: {scenario}")

    res = SESSION.post(f"{BASE_URL}/api/logout",
                       headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert res.status_code == 204, f"Logout must be 204, got {res.status_code}"

    refresh_data = {"grant_type": "refresh_token", "refresh_token": tokens['refresh_token']}
    refresh_auth = None
    if is_public:
        refresh_data["client_id"] = client_id
    else:
        refresh_auth = (client_id, case['client_secret'])
    res_ref = SESSION.post(f"{BASE_URL}/api/token", data=refresh_data, auth=refresh_auth)
    assert res_ref.status_code == 400, \
        f"Refresh after logout must fail with 400, got {res_ref.status_code}"
    # Logout is idempotent.
    res2 = SESSION.post(f"{BASE_URL}/api/logout",
                        headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert res2.status_code == 204, "Repeated logout must still be 204"

def run_cors(case):
    """CORS middleware policy (S-30: JS/API routes require CORS)."""
    method = case.get('method', 'GET')
    path = case.get('path', '/.well-known/openid-configuration')
    origin = case.get('origin', 'http://localhost:8080')
    send_origin = not case.get('omit_origin', False)
    exp_status = case.get('expected_status', 200)

    headers = {}
    if send_origin:
        headers["Origin"] = origin
    res = SESSION.request(method, f"{BASE_URL}{path}", headers=headers)
    assert res.status_code == exp_status, \
        f"CORS {method} {path} origin={origin!r}: expected {exp_status}, got {res.status_code}"

    if exp_status not in (200, 204):
        return
    if case.get('preflight'):
        # Preflight response carries the allow-list headers (S-30).
        assert res.headers.get("Access-Control-Allow-Origin") == origin, \
            "Preflight must echo the allowed origin"
        allow_methods = res.headers.get("Access-Control-Allow-Methods", "")
        assert "POST" in allow_methods and "GET" in allow_methods, \
            f"Preflight Allow-Methods mismatch: {allow_methods!r}"
        allow_headers = res.headers.get("Access-Control-Allow-Headers", "")
        assert "Authorization" in allow_headers and "Content-Type" in allow_headers, \
            f"Preflight Allow-Headers mismatch: {allow_headers!r}"
    elif 'expect_acao' in case:
        if case['expect_acao']:
            assert res.headers.get("Access-Control-Allow-Origin") == origin, \
                "Allowed origin must be echoed in Access-Control-Allow-Origin"
        else:
            assert "Access-Control-Allow-Origin" not in res.headers, \
                "No CORS header expected on this route"
    elif send_origin and exp_status == 200 and path != "/jwks.json":
        # Non-JWKS API routes behind the middleware always echo allowed origins.
        assert res.headers.get("Access-Control-Allow-Origin") == origin, \
            "Allowed origin must be echoed in Access-Control-Allow-Origin"


# --- Minimal Ed25519 signature verifier (RFC 8032, Section 5.1.7) ---
# Stdlib only (hashlib). Used to prove tokens are really signed by the JWKS key.

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _ed_inv(x):
    return pow(x, _Q - 2, _Q)


_D = (-121665 * _ed_inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _ed_recover_x(y):
    xx = ((y * y - 1) * _ed_inv((_D * y * y + 1) % _Q)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


_BX = _ed_recover_x((4 * _ed_inv(5)) % _Q)
_BASE_POINT = (_BX, (4 * _ed_inv(5)) % _Q)


def _ed_add(p, q):
    # Twisted Edwards addition (a = -1, i.e. -x^2 + y^2 = 1 + d*x^2*y^2):
    # x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    # y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
    x1, y1 = p
    x2, y2 = q
    x3 = ((x1 * y2 + x2 * y1) * _ed_inv((1 + _D * x1 * x2 * y1 * y2) % _Q)) % _Q
    y3 = ((y1 * y2 + x1 * x2) * _ed_inv((1 - _D * x1 * x2 * y1 * y2) % _Q)) % _Q
    return (x3, y3)


def _ed_scalarmult(p, e):
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        e >>= 1
    return q


def _ed_decode_point(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _ed_recover_x(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _Q - x
    return (x, y)


def _ed_encode_point(p):
    x, y = p
    return (((y | ((x & 1) << 255))) % (1 << 256)).to_bytes(32, "little")


def ed25519_verify(signing_input, signature, pubkey):
    """Verify an Ed25519 signature. All args are bytes. Returns bool."""
    try:
        if len(signature) != 64 or len(pubkey) != 32:
            return False
        a_point = _ed_decode_point(pubkey)
        if a_point is None:
            return False
        # Reject small-order public keys (RFC 8032 Section 5.1.7).
        if _ed_encode_point(_ed_scalarmult(a_point, _L)) != _ed_encode_point((0, 1)):
            return False
        r_point = _ed_decode_point(signature[:32])
        if r_point is None:
            return False
        s_int = int.from_bytes(signature[32:], "little")
        if s_int >= _L:
            return False
        h = hashlib.sha512(signature[:32] + pubkey + signing_input).digest()
        k = int.from_bytes(h, "little") % _L
        s_b = _ed_scalarmult(_BASE_POINT, s_int)
        r_ka = _ed_add(r_point, _ed_scalarmult(a_point, k))
        return _ed_encode_point(s_b) == _ed_encode_point(r_ka)
    except Exception:
        return False
