# Rudoidc: A Simplified OIDC Provider in Rust

This project is a simplified, demonstration-purpose OpenID Connect (OIDC) provider written in Rust. It implements two primary OAuth 2.0 grant types, making it suitable for learning and testing OIDC flows.

1.  **Authorization Code Grant with PKCE**: For interactive user authentication in web applications (SPAs).
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

For this demonstration, all configuration is hardcoded in `/src/main.rs`:

-   **Issuer URL**: `https://auth.sr.example.com:8000`
-   **Listen Address**: `0.0.0.0:8082`
-   **Test Users**: A `HashMap` of users and passwords.
-   **Test Clients**: A `HashMap` of clients, their redirect URIs, and audiences.
-   **Client Credentials**: A `HashMap` of credentials for the M2M flow.

You can modify these directly in the source code to fit your testing needs.

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