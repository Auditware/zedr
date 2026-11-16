use std::net::{IpAddr, SocketAddr};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;

use crate::api::AppState;
use crate::auth::{authenticate, hash_api_key, JwtSecret, User};
use crate::error::AppError;

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let jwt_secret = JwtSecret::from_env()
        .map_err(|e| AppError::Config(e))?;

    // Try JWT token first
    if let Some(auth_header) = request.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                match authenticate(&state.pool, token, &jwt_secret.0).await {
                    Ok(user) => {
                        request.extensions_mut().insert(user);
                        return Ok(next.run(request).await);
                    }
                    Err(AppError::Unauthorized) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }

    // Try API key
    if let Some(api_key) = request
        .headers()
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
    {
        let key_hash = hash_api_key(api_key);
        let now = chrono::Utc::now().timestamp();

        let user: Option<(String, String, String)> = sqlx::query_as(
            "SELECT u.id, u.username, u.role 
             FROM users u
             JOIN api_keys k ON u.id = k.user_id
             WHERE k.key_hash = ? 
             AND k.expires_at > ?
             AND k.revoked_at IS NULL
             AND u.disabled_at IS NULL",
        )
        .bind(&key_hash)
        .bind(now)
        .fetch_optional(&state.pool)
        .await?;

        if let Some((id, username, role)) = user {
            let _: Result<_, sqlx::Error> = sqlx::query(
                "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?",
            )
            .bind(now)
            .bind(&key_hash)
            .execute(&state.pool)
            .await;

            let user = User {
                id,
                username,
                role,
                impersonator: None,
            };
            request.extensions_mut().insert(user);
            return Ok(next.run(request).await);
        }
    }

    Err(AppError::Unauthorized)
}

const AGENT_FACING_PATHS: &[&str] = &[
    "/api/events",
    "/api/windows",
    "/api/proofs",
    "/api/agents/register",
    "/install.ps1",
    "/install.sh",
    "/health",
    "/healthz",
    "/readyz",
];

const AGENT_FACING_PREFIXES: &[&str] = &["/api/installers/binaries/", "/api/agents/"];

pub fn is_agent_facing_path(path: &str) -> bool {
    AGENT_FACING_PATHS.contains(&path) || AGENT_FACING_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

pub fn parse_operator_allowlist(raw: &str) -> Result<Vec<IpNet>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| format!("Invalid CIDR in operator allowlist: {}", entry))
        })
        .collect()
}

pub fn peer_is_allowed(allowlist: &[IpNet], peer: IpAddr) -> bool {
    let peer = peer.to_canonical();
    allowlist.iter().any(|network| network.contains(&peer))
}

pub async fn operator_allowlist(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    if state.operator_allowlist.is_empty() || is_agent_facing_path(request.uri().path()) {
        return Ok(next.run(request).await);
    }

    match peer {
        Some(ConnectInfo(address)) if peer_is_allowed(&state.operator_allowlist, address.ip()) => {
            Ok(next.run(request).await)
        }
        _ => Err(AppError::Forbidden),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_paths_are_public_and_operator_paths_are_not() {
        for path in ["/api/events", "/api/windows", "/api/proofs", "/api/agents/register", "/api/agents/abc/upgrade-binary", "/api/installers/binaries/windows-arm64", "/install.ps1", "/install.sh", "/healthz", "/readyz", "/health"] {
            assert!(is_agent_facing_path(path), "{} is agent facing", path);
        }
        for path in ["/", "/admin/agents", "/assets/index.js", "/api/admin/agents", "/api/admin/events", "/api/admin/events/stream", "/api/auth/login", "/api-docs/openapi.json", "/api/eventsx", "/api/windows/1", "/api/admin/ruleset", "/install.ps1.bak"] {
            assert!(!is_agent_facing_path(path), "{} is operator surface", path);
        }
    }

    #[test]
    fn test_allowlist_parses_cidrs_and_bare_addresses() {
        let allowlist = parse_operator_allowlist(" 203.0.113.0/24, 198.51.100.7 ,2001:db8::/32,").unwrap();
        assert_eq!(allowlist.len(), 3);
        assert!(peer_is_allowed(&allowlist, "203.0.113.200".parse().unwrap()));
        assert!(peer_is_allowed(&allowlist, "198.51.100.7".parse().unwrap()));
        assert!(peer_is_allowed(&allowlist, "2001:db8::1".parse().unwrap()));
        assert!(!peer_is_allowed(&allowlist, "198.51.100.8".parse().unwrap()));
        assert!(!peer_is_allowed(&allowlist, "192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_peer_matches_ipv4_rule() {
        let allowlist = parse_operator_allowlist("203.0.113.0/24").unwrap();
        assert!(peer_is_allowed(&allowlist, "::ffff:203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn test_invalid_allowlist_entry_is_an_error() {
        assert!(parse_operator_allowlist("203.0.113.0/24, not-a-network").is_err());
        assert!(parse_operator_allowlist("").unwrap().is_empty());
    }
}
