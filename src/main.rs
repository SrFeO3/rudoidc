//! A simplified OIDC (OpenID Connect) provider written in Rust.
//!
//! This server is designed for demonstration purposes and supports three primary client types:
//! 1. **Pure SPA (Public Client)**
//!    - Flow: Authorization Code Flow with PKCE
//!    - Client Secret: None
//!    - Nonce: Required
//! 2. **BFF (Confidential Client)**
//!    - Flow: Authorization Code Flow
//!    - Client Secret: Required
//!    - Nonce: Required
//!    - PKCE: Optional (used for defense-in-depth)
//! 3. **M2M (Machine-to-Machine)**
//!    - Grant: Client Credentials Grant
//!    - Client Secret: Required
//!    - Nonce: Not required
//!
//! Key Functionalities:
//! - User login via a simple HTML form.
//! - An OIDC-compliant authentication flow for multiple client applications.
//! - Token refreshing using Refresh Tokens.
//! - M2M token issuance via Client Credentials Grant with HTTP Basic Authentication.
//! - A JWKS endpoint for clients to retrieve public keys for token signature validation.
//! - An OIDC discovery endpoint for clients to automatically configure themselves.
//! - Concurrency Safety: Uses `Arc<Mutex<...>>` to protect shared in-memory data (like authorization codes), making it safe for concurrent requests on a single instance. However, this approach does not scale across multiple server instances.
//!
//! OIDC Implementation Details:
//! This server implements a specific subset of the OIDC standard tailored for this demo.
//! - **Flows**: Authorization Code Flow (with PKCE) and Client Credentials Grant.
//! - **Client Types**: Supports both Public Clients (SPAs) and Confidential Clients (BFFs, Backend Services).
//! - **Security**:
//!   - PKCE: Enforced for Public Clients, optional for Confidential Clients.
//!   - Client Secret: Verified for Confidential Clients.
//!   - Nonce: Supported for OIDC flows.
//!   - **Scope Validation**: The server validates that requested scopes (`openid`, `profile`, `offline_access`) are from a known list. The `openid` scope is mandatory.
//! - Token Format: ID Tokens and Access Tokens are issued as JWTs (JSON Web Tokens).
//! - Signing Algorithm: All JWTs are signed using the EdDSA (Edwards-curve Digital Signature Algorithm) with Ed25519.
//! - Standard & Version: This implementation is based on the core features of OpenID Connect 1.0, the foundational set of specifications finalized in 2014. The official specifications can be found at the OpenID Foundation: https://openid.net/connect/
//! - Constituent Specifications: OIDC 1.0 is a "specification family" built upon several standards:
//!   - **OAuth 2.0 (RFC 6749)**: The core authorization framework.
//!     - Relevant in `main.rs`: The `authorize_handler` initiates the flow, and `api_token_handler` exchanges codes/tokens based on `grant_type`.
//!   - **OIDC Core 1.0**: Adds the authentication layer (e.g., ID Token, `/userinfo` endpoint).
//!     - Relevant in `main.rs`: The `create_signed_id_token` function generates the ID Token, and `api_user_handler` provides user claims.
//!   - **OIDC Discovery 1.0**: Enables clients to dynamically find configuration endpoints.
//!     - Relevant in `main.rs`: The `discovery_handler` implements the `/.well-known/openid-configuration` endpoint.
//!   - **JWT (RFC 7519)**: Defines the token format.
//!     - Relevant in `main.rs`: The `serde_json::json!` macro in token creation functions defines standard claims (iss, sub, aud, exp, iat).
//!   - **JWS (RFC 7515) & JWK (RFC 7517)**: Define token signing and public key formats.
//!     - Relevant in `main.rs`: The `jwks_handler` serves the public key in JWK format, and the `jsonwebtoken::encode` calls produce JWS-signed tokens.
//!
//! OIDC Flow Considerations:
//! OAuth 2.0 and OIDC define several "grant types" or flows for different use cases.
//!
//! 1. Authorization Code Flow:
//!    - Description: The most secure and common flow for web/mobile apps with a user. The client receives a temporary code, which it exchanges for tokens via a back-channel request.
//!    - Usage: Recommended for most clients. This server implements this flow with the PKCE extension.
//! 2. Client Credentials Flow:
//!    - Description: Used for non-interactive, machine-to-machine (M2M) communication where the client authenticates itself.
//!    - Usage: Ideal for backend services or daemons authenticating themselves. This server implements this flow.
//! 3. Resource Owner Password Credentials Flow, Implicit Flow, Hybrid Flow, Device Authorization Flow, CIBA, etc.
//!    - These are other standard flows for various use cases, which are not implemented in this demo server.
//!
//! State Management & Credential Lifecycle:
//! For simplicity, this server uses volatile in-memory storage for its stateful resources, which is not suitable for production (a persistent database is required).
//! This data is lost on restart. The server manages the lifecycle of the following credentials:
//!
//! - **Authorization Code** (Stateful, stored in `auth_codes` map):
//!   A short-lived (e.g., 1 min), single-use code created upon login. It is consumed during token exchange and then deleted,
//!   or removed by a background cleanup task if it expires unused.
//! - **Refresh Token** (Stateful, stored in `refresh_tokens` map):
//!   A long-lived (e.g., 30 days) token for renewing sessions. It is created during the initial token exchange and stored on both
//!   server and client. It persists until it expires (and is cleaned up) or is explicitly revoked via logout.
//! - **Access Token** (Stateless, not stored on server):
//!   A short-lived (e.g., 10 sec in this demo) token for API access. It is created and transmitted to the client.
//!   Its validity is checked by the resource server (backend) on each use.
//! - **ID Token** (Stateless, not stored on server):
//!   A short-lived (e.g., 1 hour) token containing user identity. It is created and transmitted to the client for parsing
//!   and is not sent to resource APIs.
//!
//! Key Security Mechanisms & Best Practices:
//! - **State Parameter**: A random, single-use value generated by the client and sent in the `/authorize` request. The server echoes it back in the redirect, and the client must verify it matches the original value. This mitigates Cross-Site Request Forgery (CSRF) attacks.
//! - **Short-Lived Access Tokens**: Minimizes the window of opportunity for an attacker if an access token is compromised. The use of refresh tokens provides a better user experience without sacrificing security.
//! - **Refresh Token Revocation**: The `/api/logout` endpoint allows for explicit server-side revocation of refresh tokens, preventing their further use.
//! - **HTTPS (Production Requirement)**: While this demo runs on HTTP for simplicity, a production environment MUST use HTTPS for all communication to protect credentials from being intercepted.
//!
//! Web Entry Points (Endpoints):
//! The server's endpoints are organized by their intended consumer and access control method:
//! - Browser-Facing (e.g., /authorize, /login): Accessed via standard page navigation. No CORS needed.
//! - Server-to-Server (e.g., /jwks.json): Publicly accessible by backend services for token validation. No CORS needed.
//! - JavaScript/API (e.g., `/.well-known/...`, `/api/*`): Accessed by the frontend SPA. Requires CORS middleware.
//!
//! The main endpoints are:
//! - **Configuration & Discovery**:
//!   - `/.well-known/openid-configuration`: Provides OIDC discovery information. Its path is fixed by the "OpenID Connect Discovery 1.0" specification.
//!   - `/jwks.json`: Exposes the JSON Web Key Set (JWKS) for clients to verify JWT signatures. Its location is published via the `jwks_uri` field in the discovery document.
//! - **Authentication Flow & API**:
//!   - `/authorize`: Starts the user authentication flow by rendering the login page.
//!   - `/login`: Handles credential submission and issues an authorization code.
//!   - `/api/token`: Exchanges codes or refresh tokens for access/ID tokens. Also handles Client Credentials grant.
//!   - `/api/userinfo`: A protected endpoint that returns information about the authenticated user.
//!   - `/api/logout`: Revokes refresh tokens for a user session.
//!
//! Note: This is a minimal implementation for a demo. For production use,
//! consider using a certified OIDC provider and a more robust session/token storage mechanism.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    extract::{Form, State},
    extract::Query,
    http::{self, header, HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize}; // Ensure serde_yaml is added to Cargo.toml
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

// serverConfig holds common configuration values for the entire server.
#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    /// The public-facing issuer URL for OIDC discovery and JWT 'iss' claims. (Application-level)
    issuer: String,
    /// The internal network address (IP:PORT) the server process binds to. (Infrastructure-level)
    listen_address: String,
    /// The leeway in seconds for JWT expiration validation to account for clock skew.
    #[serde(default)]
    leeway_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    server: ServerConfig,
    users: HashMap<String, User>,
    clients: HashMap<String, Client>,
    basic_auth_credentials: HashMap<String, BasicAuthCredential>,
}

// User represents a user in the system with their profile information.
// This struct implements a subset of the standard claims associated with the OIDC 'profile' scope.
// For a full list of standard claims, see the OpenID Connect Core 1.0 specification, section 5.1:
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
// This struct is for human users who authenticate via the Authorization Code Flow.
// For machine-to-machine authentication, see BasicAuthCredential.
#[derive(Clone, Deserialize)]
struct User {
    password: String,
    family_name: String,
    given_name: String,
    preferred_username: String,
}

// BasicAuthCredential defines a username and password pair for Client Credentials Grant.
// This allows a single client application to have multiple, distinct credentials (e.g., for different services or jobs).
#[derive(Debug, Clone, Deserialize)]
struct BasicAuthCredential {
    password: String,
    client_id: String, // The client application this credential belongs to.
}

// Custom Debug implementation for User to redact the password in logs.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("Password", &"***REDACTED***")
            .field("family_name", &self.family_name)
            .field("given_name", &self.given_name)
            .field("preferred_username", &self.preferred_username)
            .finish()
    }
}

/// OAuth OIDC client
#[derive(Debug, Clone, PartialEq, Deserialize)]
enum ClientType {
    Public,       // For SPAs, cannot keep a secret.
    Confidential, // For BFFs or traditional web apps, can keep a secret.
}

#[derive(Debug, Clone, Deserialize)]
struct Client {
    client_type: ClientType,
    allowed_redirect_uris: HashSet<String>,
    // DefaultScope specifies the scope to be used when a client omits the 'scope' parameter.
    // It essentially acts as a "fallback scope". The term "Default Scope" is used here
    // to align with common OIDC terminology, although its role is to handle missing parameters.
    default_scope: String,
    audience: String,
    access_token_lifetime_seconds: i64,
    refresh_token_lifetime_seconds: i64,
    id_token_lifetime_seconds: i64,
    client_secret: Option<String>,
}

// AuthCodeInfo holds information related to an authorization code.
#[derive(Debug, Clone)]
struct AuthCodeInfo {
    username: String,
    client_id: String, // The client this code was issued for.
    scope: String, // The scope requested by the client.
    code_challenge: String, // The PKCE code challenge.
    code_challenge_method: String, // The PKCE code challenge method (e.g., "S256").
    nonce: Option<String>,
    expires_at: DateTime<Utc>, // The expiration time of the code.
}

// RefreshTokenInfo holds information related to a refresh token.
#[derive(Debug, Clone)]
struct RefreshTokenInfo {
    username: String,
    client_id: String,
    scope: String,
    expires_at: DateTime<Utc>,
}

/// The shared application state, accessible from all handlers.
#[derive(Clone)]
struct AppState {
    server_config: Arc<ServerConfig>,
    users: Arc<HashMap<String, User>>,
    clients: Arc<HashMap<String, Client>>,
    basic_auth_credentials: Arc<HashMap<String, BasicAuthCredential>>,
    signing_key: Arc<SigningKey>,
    allowed_origins: Arc<HashSet<String>>,
    signing_key_id: Arc<String>,
    // In-memory store for authorization codes. Protected by a Mutex for concurrent access.
    auth_codes: Arc<Mutex<HashMap<String, AuthCodeInfo>>>,
    // In-memory store for refresh tokens.
    refresh_tokens: Arc<Mutex<HashMap<String, RefreshTokenInfo>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration from file specified by CONFIG_FILE env var, defaulting to conf/config.yaml
    let config_path = std::env::var("CONFIG_FILE").unwrap_or_else(|_| "conf/config.yaml".to_string());
    info!(config_path, "Loading configuration...");
    let config_content = std::fs::read_to_string(&config_path)?;
    let app_config: AppConfig = serde_yaml::from_str(&config_content)?;

    let server_config = Arc::new(app_config.server);
    let users = app_config.users;
    let clients = app_config.clients;
    let basic_auth_credentials = app_config.basic_auth_credentials;

    info!(user_count = users.len(), client_count = clients.len(), "Configuration loaded.");

    info!("Generating Ed25519 key pair...");
    let mut rng = OsRng;
    let signing_key = Arc::new(SigningKey::generate(&mut rng));
    info!("Key pair generated successfully.");

    // Pre-calculate the set of allowed origins at server startup.
    let mut allowed_origins = HashSet::new();
    for client in clients.values() {
        for uri_str in &client.allowed_redirect_uris {
            if let Ok(uri) = uri_str.parse::<http::Uri>() {
                if let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) {
                    let origin = format!("{}://{}", scheme, authority);
                    allowed_origins.insert(origin);
                }
            }
        }
    }
    info!(origins = ?allowed_origins, "Allowed CORS origins configured.");

    // Create the in-memory stores that need to be shared with the cleanup task.
    let auth_codes = Arc::new(Mutex::new(HashMap::new()));
    let refresh_tokens = Arc::new(Mutex::new(HashMap::new()));

    // Create the shared application state.
    let app_state = AppState {
        server_config,
        users: Arc::new(users),
        clients: Arc::new(clients),
        basic_auth_credentials: Arc::new(basic_auth_credentials),
        signing_key,
        allowed_origins: Arc::new(allowed_origins),
        signing_key_id: Arc::new("SigningKeyID001".to_string()),
        auth_codes: auth_codes.clone(),
        refresh_tokens: refresh_tokens.clone(),
    };

    // --- 1. Browser/Human-facing endpoints (No CORS needed) ---
    // These are used for browser page navigation and form submissions.
    let browser_routes = Router::new()
        .route("/authorize", get(authorize_handler))
        .route("/login", post(login_post_handler));

    // Start a background task to clean up expired resources.
    tokio::spawn(start_cleanup_task(auth_codes, refresh_tokens));

    // --- 2. Server-to-server communication endpoints (No CORS needed) ---
    // The backend server fetches the public key to verify JWT signatures.
    let server_routes = Router::new().route("/jwks.json", get(jwks_handler));

    // --- 3. API endpoints for frontend JS (CORS required) ---
    // All routes defined here are protected by the CORS middleware.
    let api_routes = Router::new()
        // Standard OIDC endpoint. Requires CORS for dynamic configuration loading from JS.
        .route("/.well-known/openid-configuration", get(discovery_handler))
        // Sub-router for API endpoints with the /api/ prefix.
        .nest(
            "/api",
            Router::new()
                .route("/token", post(api_token_handler))
                .route("/logout", post(logout_handler))
                .route("/userinfo", get(api_user_handler)),
        )
        .layer(middleware::from_fn_with_state(app_state.allowed_origins.clone(), enforce_cors_middleware));

    // --- Combine all routers into the final application ---
    let app = Router::new()
        .route("/", get(root_handler))
        .merge(browser_routes)
        .merge(server_routes)
        .merge(api_routes)
        .with_state(app_state.clone());

    // Prepare variables for the startup log
    let server_name = &app_state.server_config.issuer;
    let tcp_bind_address = &app_state.server_config.listen_address;
    let server_port = tcp_bind_address.split(':').last().unwrap_or("unknown");
    let user_count = app_state.users.len();
    let client_count = app_state.clients.len();

    info!(
        "OIDC Provider started (Version: {}, PID: {}) with config for: {}, {}, {}, {}, Users: {}, Clients: {}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        server_name,
        server_port,
        tcp_bind_address,
        config_path,
        user_count,
        client_count
    );

    let listener = tokio::net::TcpListener::bind(&app_state.server_config.listen_address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// A middleware that enforces the CORS (Cross-Origin Resource Sharing) policy.
/// - Handles `OPTIONS` preflight requests, returning an empty response with CORS headers if allowed.
/// - For actual requests (like `GET`, `POST`), it adds the `Access-Control-Allow-Origin` header to the response if allowed.
/// - Blocks requests from disallowed origins by returning a 403 Forbidden.
async fn enforce_cors_middleware(
    State(allowed_origins): State<Arc<HashSet<String>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    info!(
        method = %request.method(),
        path = %request.uri().path(),
        origin = ?request.headers().get(header::ORIGIN).map(|v| v.to_str().unwrap_or("")),
        "CORS Middleware: Received request"
    );

    let origin = request.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok());

    // Only perform CORS checks if the Origin header is present.
    let origin_str = match origin {
        Some(o) => o,
        // Requests without an Origin header (e.g., server-to-server) are passed through.
        None => {
            info!("CORS Middleware: No Origin header, passing through. (Not a cross-origin browser request)");
            return next.run(request).await;
        }
    };

    // Check if the origin is in the allowlist.
    if !allowed_origins.contains(origin_str) {
        // If the origin is not allowed, immediately terminate with a 403 Forbidden.
        warn!(origin = %origin_str, "CORS Middleware: Blocked request from disallowed origin");
        return (StatusCode::FORBIDDEN, "CORS: Disallowed origin").into_response();
    }

    let origin_header = origin_str.parse().unwrap();

    // Respond to preflight (OPTIONS) requests.
    if request.method() == Method::OPTIONS {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_header)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST, GET, OPTIONS")
            //.header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Content-Type, Authorization",
            )
            .body(Body::empty())
            .unwrap();
    }

    // Add CORS header to the response for actual requests.
    let mut response = next.run(request).await;
    response.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_header);
    //response.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".parse().unwrap());
    response
}

// startCleanupTask starts a background task that periodically cleans up expired resources.
async fn start_cleanup_task(
    auth_codes: Arc<Mutex<HashMap<String, AuthCodeInfo>>>,
    refresh_tokens: Arc<Mutex<HashMap<String, RefreshTokenInfo>>>,
) {
    // For demo purposes, run the cleanup task every minute.
    // In a production environment, a longer interval like 10-30 minutes might be more appropriate.
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        info!("Running background cleanup task for stale resources...");

        let now = Utc::now();

        // 1. Clean up expired authorization codes.
        let cleaned_auth_codes = {
            let mut codes = auth_codes.lock().unwrap();
            let initial_len = codes.len();
            codes.retain(|_, info| info.expires_at > now);
            initial_len - codes.len()
        };
        info!("Cleanup: Removed {} expired authorization code(s).", cleaned_auth_codes);

        // 2. Clean up expired refresh tokens.
        let cleaned_refresh_tokens = {
            let mut tokens = refresh_tokens.lock().unwrap();
            let initial_len = tokens.len();
            tokens.retain(|_, info| info.expires_at > now);
            initial_len - tokens.len()
        };
        info!("Cleanup: Removed {} expired refresh token(s).", cleaned_refresh_tokens);
    }
}

// page handlers

async fn discovery_handler(
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let config = app_state.server_config;
    let discovery_doc = serde_json::json!({
        "issuer": config.issuer,
        "authorization_endpoint": format!("{}/authorize", config.issuer),
        "token_endpoint": format!("{}/api/token", config.issuer),
        "userinfo_endpoint": format!("{}/api/userinfo", config.issuer),
        "jwks_uri": format!("{}/jwks.json", config.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    });
    info!("Served OIDC discovery configuration");
    (StatusCode::OK, Json(discovery_doc))
}

async fn jwks_handler(
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let verifying_key = app_state.signing_key.verifying_key();
    let x = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());

    let jwks = serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": &*app_state.signing_key_id,
            "use": "sig",
            "alg": "EdDSA",
            "x": x,
        }]
    });

    let mut headers = http::HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "public, max-age=86400".parse().unwrap());
    info!("Served JWKS");
    (headers, Json(jwks))
}

async fn authorize_handler(
    State(app_state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    uri: http::Uri,
) -> impl IntoResponse {
    // Extract and validate client_id
    let client_id = match params.get("client_id") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "client_id is required").into_response(),
    };
    let client = match app_state.clients.get(client_id.as_str()) {
        Some(c) => c,
        None => {
            warn!("Invalid authorize request: unknown client_id={}", client_id);
            return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response();
        }
    };

    // Extract and validate redirect_uri
    let redirect_uri = match params.get("redirect_uri") {
        Some(uri) => uri,
        None => return (StatusCode::BAD_REQUEST, "redirect_uri is required").into_response(),
    };
    if !client.allowed_redirect_uris.contains(redirect_uri) {
        warn!("Invalid authorize request for client {}: redirect_uri {} not allowed, expected uri {:?}", client_id, redirect_uri, client.allowed_redirect_uris);
        return (StatusCode::BAD_REQUEST, "Invalid redirect_uri").into_response();
    }

    // Validate nonce (Required per specification for SPA and BFF)
    if params.get("nonce").is_none() {
        warn!("Invalid authorize request: nonce is required");
        return (StatusCode::BAD_REQUEST, "nonce is required").into_response();
    }

    // Pass the original query string to the login form's action.
    info!("INFO: Displayed login page for client_id={}", client_id);
    let login_html = render_login_page(uri.query().unwrap_or(""), None);

    (StatusCode::OK, Html(login_html)).into_response()
}

async fn login_post_handler(
    State(app_state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    uri: http::Uri,
    Form(payload): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let username = match payload.get("username") {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, "username is required").into_response(),
    };
    let password = match payload.get("password") {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "password is required").into_response(),
    };

    // Authenticate user
    let user_valid = app_state
        .users
        .get(username.as_str())
        .map_or(false, |user| &user.password == password);

    if !user_valid {
        warn!("Invalid credentials for user: {}", username);
        let error_html = render_login_page(uri.query().unwrap_or(""), Some("Invalid username or password"));
        return (StatusCode::UNAUTHORIZED, Html(error_html)).into_response();
    }

    // Re-validate client and redirect_uri from query parameters
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();

    let client = match app_state.clients.get(client_id.as_str()) {
        Some(c) => c,
        None => {
            warn!("Invalid client_id in login handler: {}", client_id);
            return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response();
        }
    };

    if !client.allowed_redirect_uris.contains(&redirect_uri) {
        warn!("Invalid redirect_uri in login handler: {}", redirect_uri);
        return (StatusCode::BAD_REQUEST, "Invalid redirect_uri").into_response();
    }

    // Validate nonce (Required per specification)
    if params.get("nonce").is_none() {
        warn!("Invalid login request: nonce is required");
        return (StatusCode::BAD_REQUEST, "nonce is required").into_response();
    }

    // Determine scope
    let scope = params.get("scope").map_or_else(
        || {
            warn!("Client '{}' did not specify a 'scope'. Falling back to default scope: '{}'", client_id, client.default_scope);
            client.default_scope.clone()
        },
        |s| s.clone(),
    );

    let requested_scopes: HashSet<&str> = scope.split_whitespace().collect();
    const SUPPORTED_SCOPES: &[&str] = &["openid", "profile", "offline_access"];

    if !requested_scopes.contains("openid") {
        warn!("Invalid login request: 'openid' scope is required");
        return (StatusCode::BAD_REQUEST, "invalid_scope: 'openid' scope is required").into_response();
    }

    for s in &requested_scopes {
        if !SUPPORTED_SCOPES.contains(s) {
            warn!(client_id, scope = s, "Invalid login request: unsupported scope requested");
            return (StatusCode::BAD_REQUEST, "invalid_scope: one or more scopes are not supported").into_response();
        }
    }

    // Generate authorization code and store it with its info
    let code: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(32).map(char::from).collect();
    let code_info = AuthCodeInfo {
        username: username.clone(),
        client_id: client_id.clone(),
        scope,
        code_challenge: params.get("code_challenge").cloned().unwrap_or_default(),
        code_challenge_method: params.get("code_challenge_method").cloned().unwrap_or_default(),
        nonce: params.get("nonce").cloned(),
        expires_at: Utc::now() + chrono::Duration::minutes(1),
    };

    {
        let mut auth_codes = app_state.auth_codes.lock().unwrap();
        auth_codes.insert(code.clone(), code_info);
        info!("Issued authorization code for user '{}'. Total active codes: {}", username, auth_codes.len());
    }

    // Build the redirect URL
    let mut redirect_url = Url::parse(&redirect_uri).expect("Failed to parse redirect_uri");
    redirect_url.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &params.get("state").cloned().unwrap_or_default());

    info!(user = %username, "User authenticated successfully. Redirecting to client.");
    Redirect::to(redirect_url.as_str()).into_response()
}

async fn api_token_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let grant_type = payload.get("grant_type").map(|s| s.as_str());
    let mut client_id = payload.get("client_id").cloned().unwrap_or_default();

    // If client_id is not provided in the form body, try to extract it from the Basic Auth header.
    // This is common for Confidential Clients (BFFs) using Basic Auth for authentication.
    if client_id.is_empty() {
        if let Some(auth_header) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
            if let Some(encoded) = auth_header.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    let creds = String::from_utf8(decoded).unwrap_or_default();
                    if let Some((id, _)) = creds.split_once(':') {
                        client_id = id.to_string();
                    }
                }
            }
        }
    }

    info!(grant_type, client_id, "Token endpoint called");

    let (username, scope, audience, client_id_for_token, nonce) = match grant_type {
        Some("authorization_code") => {
            let code = payload.get("code").cloned().unwrap_or_default();

            let code_info = {
                let mut auth_codes = app_state.auth_codes.lock().unwrap();
                auth_codes.remove(&code)
            };

            let code_info = match code_info {
                Some(info) => info,
                None => {
                    warn!("Invalid authorization code used");
                    return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
                }
            };

            if Utc::now() > code_info.expires_at {
                warn!(user = %code_info.username, "Expired authorization code used");
                return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
            }

            if code_info.client_id != client_id {
                warn!(expected = %code_info.client_id, got = %client_id, "Mismatched client_id for auth code");
                return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
            }

            // Get client configuration to determine validation rules
            let client = match app_state.clients.get(client_id.as_str()) {
                Some(c) => c,
                None => {
                    // This case should ideally not be reached due to prior checks, but as a safeguard:
                    warn!(client_id, "Client not found during audience lookup in token handler");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Client configuration error").into_response();
                }
            };
            
            // --- Client Type Specific Validations ---
            match client.client_type {
                ClientType::Public => {
                    // Public clients (SPAs) MUST use PKCE and MUST NOT use a client secret.
                    let code_verifier = payload.get("code_verifier").cloned().unwrap_or_default();
                    if code_verifier.is_empty() {
                        warn!(client_id, "PKCE error: code_verifier is missing for public client");
                        return (StatusCode::BAD_REQUEST, "code_verifier is required for public clients").into_response();
                    }
                    if !verify_pkce(&code_info.code_challenge, &code_info.code_challenge_method, &code_verifier) {
                        warn!(user = %code_info.username, "PKCE verification failed for public client");
                        return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
                    }
                    info!(user = %code_info.username, "PKCE verification successful for public client");
                }
                ClientType::Confidential => {
                    // Confidential clients (BFFs) MUST authenticate with a client_secret.
                    let expected_secret = match &client.client_secret {
                        Some(s) => s,
                        None => {
                            error!(client_id, "Server configuration error: Confidential client has no secret configured.");
                            return (StatusCode::INTERNAL_SERVER_ERROR, "Server configuration error").into_response();
                        }
                    };

                    // Try to get secret from Basic Auth header first, then from the POST body.
                    let provided_secret = if let Some(auth_header) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
                        if let Some(encoded) = auth_header.strip_prefix("Basic ") {
                            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                                let creds = String::from_utf8(decoded).unwrap_or_default();
                                // We only care about the password part for client_secret validation here.
                                creds.split_once(':').map(|(_, p)| p.to_string())
                            } else { None }
                        } else { None }
                    } else {
                        payload.get("client_secret").cloned()
                    };

                    if provided_secret.as_deref() != Some(expected_secret.as_str()) {
                        warn!(client_id, "Invalid client_secret provided for confidential client");
                        return (StatusCode::UNAUTHORIZED, "Invalid client authentication").into_response();
                    }
                    info!(client_id, "Client secret verified successfully for confidential client");

                    // PKCE is optional (defense-in-depth). If a challenge was sent, the verifier must be present and valid.
                    if !code_info.code_challenge.is_empty() {
                        let code_verifier = payload.get("code_verifier").cloned().unwrap_or_default();
                        if code_verifier.is_empty() {
                            warn!(client_id, "PKCE error: code_verifier is missing for a request that used a code_challenge");
                            return (StatusCode::BAD_REQUEST, "code_verifier is required when code_challenge is used").into_response();
                        }
                        if !verify_pkce(&code_info.code_challenge, &code_info.code_challenge_method, &code_verifier) {
                            warn!(user = %code_info.username, "PKCE verification failed for confidential client");
                            return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
                        }
                        info!(user = %code_info.username, "PKCE verification successful for confidential client (defense-in-depth)");
                    }
                }
            }

            (code_info.username, code_info.scope, client.audience.clone(), client_id, code_info.nonce)
        }
        Some("refresh_token") => {
            let refresh_token = payload.get("refresh_token").cloned().unwrap_or_default();
            let token_info = {
                let refresh_tokens = app_state.refresh_tokens.lock().unwrap();
                refresh_tokens.get(&refresh_token).cloned()
            };

            let token_info = match token_info {
                Some(info) => info,
                None => {
                    warn!("Invalid refresh token used");
                    return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
                }
            };

            if Utc::now() > token_info.expires_at {
                warn!(user = %token_info.username, "Expired refresh token used");
                let mut refresh_tokens = app_state.refresh_tokens.lock().unwrap();
                refresh_tokens.remove(&refresh_token);
                return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
            }

            if token_info.client_id != client_id {
                warn!(expected = %token_info.client_id, got = %client_id, "Mismatched client_id for refresh token");
                return (StatusCode::BAD_REQUEST, "Invalid grant").into_response();
            }

            info!(user = %token_info.username, "Attempting to refresh token");
            let audience = match app_state.clients.get(client_id.as_str()) {
                Some(client) => client.audience.clone(),
                None => {
                    warn!(client_id, "Client not found during audience lookup in token handler (refresh)");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Client configuration error").into_response();
                }
            };
            (token_info.username, token_info.scope, audience, client_id, None)
        }
        Some("client_credentials") => {
            // For Client Credentials, authentication is performed via HTTP Basic Auth.
            let auth_header = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok());

            let (auth_username, auth_password) = match auth_header.and_then(|h| h.strip_prefix("Basic ")) {
                Some(encoded) => {
                    match base64::engine::general_purpose::STANDARD.decode(encoded) {
                        Ok(decoded_bytes) => {
                            let decoded_str = String::from_utf8(decoded_bytes).unwrap_or_default();
                            if let Some((u, p)) = decoded_str.split_once(':') {
                                (u.to_string(), p.to_string())
                            } else {
                                (String::new(), String::new())
                            }
                        },
                        Err(_) => (String::new(), String::new()),
                    }
                },
                None => {
                    warn!("Client credentials grant requires HTTP Basic authentication.");
                    return (StatusCode::UNAUTHORIZED, "Invalid client credentials").into_response();
                }
            };
            let cred = match app_state.basic_auth_credentials.get(auth_username.as_str()) {
                Some(c) if c.password == auth_password => c,
                _ => {
                    warn!(username = %auth_username, "Invalid client credentials provided.");
                    return (StatusCode::UNAUTHORIZED, "Invalid client credentials").into_response();
                }
            };

            let client = match app_state.clients.get(cred.client_id.as_str()) {
                Some(c) => c,
                None => {
                    error!(credential_user = %auth_username, client_id = %cred.client_id, "Credential is linked to a non-existent client_id");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Server configuration error").into_response();
                }
            };

            let scope = payload.get("scope").map_or_else(|| client.default_scope.clone(), |s| s.clone());

            // Validate scopes for M2M grant, similar to authorization code flow.
            const SUPPORTED_SCOPES: &[&str] = &["openid", "profile", "offline_access"];
            let requested_scopes: HashSet<&str> = scope.split_whitespace().collect();

            // Require 'openid' scope for consistency, even for M2M.
            if !requested_scopes.contains("openid") {
                warn!(client_id = %cred.client_id, "M2M grant: 'openid' scope is required");
                return (StatusCode::BAD_REQUEST, "invalid_scope: 'openid' scope is required").into_response();
            }

            for s in &requested_scopes {
                if !SUPPORTED_SCOPES.contains(s) {
                    warn!(client_id = %cred.client_id, scope = s, "M2M grant: unsupported scope requested");
                    return (StatusCode::BAD_REQUEST, "invalid_scope: one or more scopes are not supported").into_response();
                }
            }
            (auth_username, scope, client.audience.clone(), cred.client_id.clone(), None)
        }
        _ => {
            warn!(?grant_type, "Unsupported grant_type");
            return (StatusCode::BAD_REQUEST, "Unsupported grant_type").into_response();
        }
    };

    // For client_credentials grant, we only issue an access token.
    if grant_type == Some("client_credentials") {
        info!(service_account = %username, "Successfully validated client_credentials grant. Generating access token...");
        let now = Utc::now();
        let access_token = match create_signed_access_token(&username, &audience, &scope, &client_id_for_token, now, &app_state) {
            Ok(token) => token,
            Err(e) => {
                error!(service_account = %username, error = ?e, "Failed to sign access token for service account");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
            }
        };
        let client = app_state.clients.get(client_id_for_token.as_str()).expect("Client must exist");
        let response = serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime_seconds,
            "scope": scope,
        });
        return (StatusCode::OK, Json(response)).into_response();
    }

    info!(user = %username, "Successfully validated grant. Generating tokens...");

    let now = Utc::now();
    let id_token = match create_signed_id_token(&username, &client_id_for_token, &scope, now, &app_state, nonce) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(user = %username, error = ?e, "Failed to sign id token");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    let access_token = match create_signed_access_token(&username, &audience, &scope, &client_id_for_token, now, &app_state) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(user = %username, error = ?e, "Failed to sign access token");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    let client = app_state.clients.get(client_id_for_token.as_str()).expect("Client must exist");
    let mut response_body = serde_json::json!({
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": client.access_token_lifetime_seconds,
    });

    if grant_type == Some("authorization_code") && scope.contains("offline_access") {
        let new_refresh_token: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(64).map(char::from).collect();

        let token_info = RefreshTokenInfo {
            username: username.to_string(),
            client_id: client_id_for_token.to_string(),
            scope: scope.to_string(),
            expires_at: now + chrono::Duration::seconds(client.refresh_token_lifetime_seconds),
        };

        info!(?token_info, "Issued Refresh Token");

        {
            let mut refresh_tokens = app_state.refresh_tokens.lock().unwrap();
            refresh_tokens.insert(new_refresh_token.clone(), token_info);
            info!(user = %username, "Issued new refresh token");
        }
        response_body["refresh_token"] = serde_json::Value::String(new_refresh_token);
    }

    info!(user = %username, ?grant_type, "Successfully issued tokens");
    (StatusCode::OK, Json(response_body)).into_response()
}

fn create_signed_id_token(username: &str, client_id: &str, scope: &str, now: DateTime<Utc>, app_state: &AppState, nonce: Option<String>) -> Result<String, jsonwebtoken::errors::Error> {
    let client = app_state.clients.get(client_id).expect("Client must exist");
    let iat = now.timestamp();

    // Start with base claims required by OIDC.
    let mut claims = serde_json::json!({
        "iss": &app_state.server_config.issuer,
        "sub": username,
        "aud": client_id,
        "exp": iat + client.id_token_lifetime_seconds,
        "iat": iat,
        // As a default, set name to the username. This will be overridden if profile scope is present.
        "name": username,
    });

    if let Some(n) = nonce {
        claims.as_object_mut().unwrap().insert("nonce".to_string(), serde_json::Value::String(n));
    }

    // If the "profile" scope is requested, add more user profile claims.
    if scope.contains("profile") {
        if let Some(user) = app_state.users.get(username) {
            let claims_map = claims.as_object_mut().unwrap();
            claims_map.insert("family_name".to_string(), serde_json::Value::String(user.family_name.clone()));
            claims_map.insert("given_name".to_string(), serde_json::Value::String(user.given_name.clone()));
            claims_map.insert("preferred_username".to_string(), serde_json::Value::String(user.preferred_username.clone()));
            // 'name' can be constructed from given and family names for a better representation.
            claims_map.insert("name".to_string(), serde_json::Value::String(format!("{} {}", user.given_name, user.family_name)));
        }
    }

    info!(?claims, "Issued ID Token");

    let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(app_state.signing_key_id.to_string());
    let pem = app_state.signing_key.to_pkcs8_pem(Default::default())
        .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)?;
    let encoding_key = EncodingKey::from_ed_pem(pem.as_bytes())?;
    encode(&header, &claims, &encoding_key)
}

fn create_signed_access_token(username: &str, audience: &str, scope: &str, client_id: &str, now: DateTime<Utc>, app_state: &AppState) -> Result<String, jsonwebtoken::errors::Error> {
    #[derive(Serialize, Debug)]
    struct Claims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        cid: &'a str,
        scp: Vec<&'a str>,
    }

    let client = app_state.clients.get(client_id).expect("Client must exist");
    let iat = now.timestamp();

    let claims = Claims {
        iss: &app_state.server_config.issuer,
        sub: username,
        aud: audience,
        exp: iat + client.access_token_lifetime_seconds,
        iat,
        cid: client_id,
        scp: scope.split(' ').collect(),
    };

    info!(?claims, "Issued Access Token");

    let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(app_state.signing_key_id.to_string());
    let pem = app_state.signing_key.to_pkcs8_pem(Default::default())
        .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)?;
    let encoding_key = EncodingKey::from_ed_pem(pem.as_bytes())?;
    encode(&header, &claims, &encoding_key)
}

fn verify_pkce(challenge: &str, method: &str, verifier: &str) -> bool {
    if method != "S256" {
        warn!(method, "Unsupported code_challenge_method");
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();
    let encoded = URL_SAFE_NO_PAD.encode(result);
    encoded == challenge
}

/// Helper function to render the login page HTML with an optional error message.
fn render_login_page(query: &str, error: Option<&str>) -> String {
    let error_html = error.map_or(String::new(), |e| format!("<p class=\"error\">{}</p>", e));
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <form method="post" action="/login?{}">
        <h2>Login</h2>
        <div><label for="username">Username:</label><input type="text" id="username" name="username" value="suzuki" required></div>
        <div><label for="password">Password:</label><input type="password" id="password" name="password" value="password" required></div>
        <button type="submit">Log In</button>
        {}
    </form>
</body>
</html>"#,
        query, error_html
    )
}

async fn api_user_handler(
    State(app_state): State<AppState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let auth_header = request.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok());

    let token_string = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => token,
        None => {
            return (StatusCode::UNAUTHORIZED, "Authorization header required").into_response();
        }
    };

    // Define the claims we expect in the access token.
    #[derive(Deserialize)]
    struct AccessTokenClaims { sub: String }

    let x = URL_SAFE_NO_PAD.encode(app_state.signing_key.verifying_key().as_bytes());
    let decoding_key = match DecodingKey::from_ed_components(&x) {
        Ok(key) => key,
        Err(e) => {
            error!(error = ?e, "Failed to create EdDSA decoding key");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };
    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    // For userinfo, we don't strictly need to validate the audience, as long as the token is valid.
    validation.validate_aud = false;
    validation.leeway = app_state.server_config.leeway_seconds;

    let claims = match decode::<AccessTokenClaims>(token_string, &decoding_key, &validation) {
        Ok(token_data) => token_data.claims,
        Err(e) => {
            warn!(error = ?e, "Invalid token provided to userinfo endpoint");
            return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
        }
    };
    
    let user_info = match app_state.users.get(&claims.sub) {
        Some(user) => serde_json::json!({
            "sub": claims.sub,
            "family_name": user.family_name,
            "given_name": user.given_name,
            "preferred_username": user.preferred_username,
        }),
        None => {
            error!(user = %claims.sub, "User from valid token not found in state");
            return (StatusCode::INTERNAL_SERVER_ERROR, "User not found").into_response();
        }
    };

    info!(user = %user_info["sub"], "Successfully served userinfo");
    (StatusCode::OK, Json(user_info)).into_response()
}

async fn root_handler() -> &'static str {
    "Hello rudoidc world"
}

async fn logout_handler(
    State(app_state): State<AppState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let auth_header = request.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok());

    let token_string = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => token,
        None => {
            // If no token is present, there's nothing to do on the server side.
            return StatusCode::NO_CONTENT;
        }
    };

    // We need to parse the token to get the user and client ID, but we don't need to validate the expiration.
    // A user should be able to log out even with an expired access token.
    #[derive(Deserialize)]
    struct LogoutClaims {
        sub: String,
        cid: String,
    }

    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_exp = false; // Don't validate expiration time
    validation.validate_aud = false; // Don't validate audience for logout

    let x = URL_SAFE_NO_PAD.encode(app_state.signing_key.verifying_key().as_bytes());
    let decoding_key = match DecodingKey::from_ed_components(&x) {
        Ok(key) => key,
        Err(e) => {
            error!(error = ?e, "Failed to create EdDSA decoding key for logout");
            // Even on failure, don't block client-side logout.
            return StatusCode::NO_CONTENT;
        }
    };
    let claims = match decode::<LogoutClaims>(token_string, &decoding_key, &validation) {
        Ok(token_data) => token_data.claims,
        Err(e) => {
            warn!(
                error = ?e,
                token = %token_string,
                "Logout attempt with invalid token"
            );
            // Don't block the client-side process even if the token is invalid.
            return StatusCode::NO_CONTENT;
        }
    };

    let username = claims.sub;
    let client_id = claims.cid;

    let revoked_count = {
        let mut refresh_tokens = app_state.refresh_tokens.lock().unwrap();
        let initial_len = refresh_tokens.len();
        refresh_tokens.retain(|_, info| !(info.username == username && info.client_id == client_id));
        initial_len - refresh_tokens.len()
    };

    if revoked_count > 0 {
        info!(
            user = %username,
            client = %client_id,
            count = revoked_count,
            "Revoked refresh token(s) upon logout."
        );
    }

    StatusCode::NO_CONTENT
}
