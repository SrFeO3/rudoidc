"""
OIDC Server Test Script
Tests the three main scenarios: M2M, Pure SPA (Public), and BFF (Confidential).
Requires: pip install requests pytest pyyaml
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

# Setup Global Session
SESSION = requests.Session()
SESSION.verify = VERIFY_SSL
if HOST_HEADER:
    SESSION.headers.update({'Host': HOST_HEADER})

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    else:
        pytest.fail(f"Unknown test type: {test_type}")

def run_discovery(case):
    res = SESSION.get(f"{BASE_URL}/.well-known/openid-configuration")
    assert res.status_code == 200, f"Discovery endpoint returned {res.status_code}"
    data = res.json()
    assert data['issuer'] == ISSUER, f"Issuer mismatch. Expected {ISSUER}, got {data['issuer']}"
    assert "EdDSA" in data['id_token_signing_alg_values_supported'], "Discovery: EdDSA not in supported algs"

def run_jwks(case):
    res = SESSION.get(f"{BASE_URL}/jwks.json")
    assert res.status_code == 200, f"JWKS endpoint returned {res.status_code}"
    data = res.json()
    keys = data.get('keys', [])
    assert len(keys) > 0, "JWKS: No keys found"
    
    key = keys[0]
    assert key['kty'] == 'OKP', f"JWKS: Expected kty=OKP, got {key.get('kty')}"
    assert key['crv'] == 'Ed25519', f"JWKS: Expected crv=Ed25519, got {key.get('crv')}"
    assert key['alg'] == 'EdDSA', f"JWKS: Expected alg=EdDSA, got {key.get('alg')}"

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

def run_m2m(case):
    # Configuration & Defaults
    username = case['username']
    password = case['password']
    scope = case.get('scope', 'openid')
    grant_type = case.get('grant_type', 'client_credentials')
    
    exp_status = case.get('expected_status', 200)

    res = SESSION.post(
        f"{BASE_URL}/api/token",
        auth=(username, password),
        data={
            "grant_type": grant_type,
            "scope": scope
        }
    )
    assert res.status_code == exp_status, f"M2M token request status mismatch. Expected {exp_status}, got {res.status_code}. Body: {res.text}"
    
    if exp_status == 200:
        data = res.json()
        assert "access_token" in data, "Response missing access_token"

def run_auth_flow(case, is_public):
    # --- Configuration & Defaults ---
    client_id = case['client_id']
    redirect_uri = case['redirect_uri']
    scope = case.get('scope', 'openid')
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
    verifier, challenge = generate_pkce() if use_pkce else (None, None)
    
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "nonce": nonce,
        "state": "test_state_val"
    }

    if use_pkce:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = pkce_method

    # Apply Login Overrides
    if case.get('omit_nonce'): del params['nonce']
    if case.get('omit_redirect_uri'): del params['redirect_uri']
    if case.get('wrong_redirect_uri'): params['redirect_uri'] = "http://evil.com/callback"
    if case.get('omit_client_id_login'): del params['client_id']
    if case.get('wrong_client_id_login'): params['client_id'] = "wrong-client"
    
    # Execute Login
    res = SESSION.post(
        f"{BASE_URL}/login",
        params=params,
        data={"username": username, "password": password},
        allow_redirects=False
    )
    
    assert res.status_code == exp_login_status, f"Login status mismatch. Expected {exp_login_status}, got {res.status_code}. Body: {res.text}"
    
    if exp_login_status != 303:
        return # Stop if we expected login to fail

    location = res.headers['Location']
    qs = parse_qs(urlparse(location).query)
    assert 'code' in qs, "Authorization code not found in redirect URL"
    code = qs['code'][0]

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
        return SESSION.post(f"{BASE_URL}/api/token", data=token_data, auth=auth)

    res = do_exchange()
    assert res.status_code == exp_token_status, f"Token exchange status mismatch. Expected {exp_token_status}, got {res.status_code}. Body: {res.text}"

    if exp_token_status != 200:
        return # Stop if we expected token exchange to fail

    data = res.json()
    assert "id_token" in data, "id_token missing from response"
    
    claims = decode_jwt_payload(data['id_token'])
    assert claims is not None, "Failed to decode ID token"
    assert claims.get("nonce") == nonce, f"Nonce mismatch. Expected {nonce}, got {claims.get('nonce')}"

    # --- Optional: UserInfo Endpoint Test ---
    if case.get('test_userinfo'):
        access_token = data.get('access_token')
        assert access_token, "Access token missing, cannot test userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        res_userinfo = SESSION.get(f"{BASE_URL}/api/userinfo", headers=headers)
        assert res_userinfo.status_code == 200, f"UserInfo request failed: {res_userinfo.text}"
        userinfo_data = res_userinfo.json()
        assert userinfo_data.get('sub') == username, f"UserInfo 'sub' mismatch. Expected {username}, got {userinfo_data.get('sub')}"

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
             assert "access_token" in res_refresh.json(), "New access token missing in refresh response"
