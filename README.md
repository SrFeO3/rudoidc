# Rudoidc: A Simplified OIDC Provider in Rust

This project is a simplified, demonstration-purpose OpenID Connect (OIDC) provider written in Rust. It implements two primary OAuth 2.0 grant types, making it suitable for learning and testing OIDC flows.

1.  **Authorization Code Grant**: For interactive user authentication in web applications (SPAs, BFFs).
2.  **Client Credentials Grant**: For non-interactive, machine-to-machine (M2M) communication.

## Getting Started

### Prerequisites

-   Rust toolchain

### Running the Server

1.  Clone the repository:
    ```sh
    git clone <repository-url>
    cd rudoidc
    ```

2.  Run the server:
    ```sh
    cargo run
    ```

By default, the server will start on `0.0.0.0:8082`.

### Configuration

The server configuration is loaded from a YAML file. By default, it looks for `conf/config.yaml`. You can specify a custom path using the `CONFIG_FILE` environment variable.

The configuration file defines:
-   **Server Settings**: Issuer URL, listen address, and clock skew leeway.
-   **Users**: Test users with passwords and profile data.
-   **Clients**: OAuth clients (SPA, BFF) with their settings (redirect URIs, secrets, etc.).
-   **Basic Auth Credentials**: Credentials for M2M flow.

## API Endpoints

### Discovery & Keys

-   `GET /.well-known/openid-configuration`: OIDC discovery document.
-   `GET /jwks.json`: JSON Web Key Set (JWKS) for token signature validation.

### Authentication Flow

-   `GET /authorize`: Renders the login page to start the user authentication flow.
-   `POST /login`: Handles user login form submission and issues an authorization code.

### Token & User API

-   `POST /api/token`: Exchanges an authorization code, refresh token, or client credentials for tokens.
-   `GET /api/userinfo`: Returns user information for a valid access token.
-   `POST /api/logout`: Revokes all refresh tokens for the user/client associated with the provided access token.

## Disclaimer

This is a minimal implementation for demonstration and educational purposes. It is **not** a certified OIDC provider and is **not suitable for production use**. For production systems, please use a battle-tested and certified OIDC solution.

## Security Notes

-   **State Management**: This server uses in-memory, `Mutex`-protected `HashMap`s for storing authorization codes and refresh tokens. This data is volatile and will be lost on restart. A persistent database is required for a production environment.
-   **HTTPS**: This demo runs on HTTP for simplicity. A production OIDC provider **MUST** use HTTPS for all communication to protect credentials.
-   **State Parameter**: The server correctly handles the `state` parameter to mitigate CSRF attacks, but it is the client's responsibility to generate and validate it.
-   **Scope Validation**: The server validates that requested scopes are within the supported list (`openid`, `profile`, `offline_access`) and that `openid` is present.