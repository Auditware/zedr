use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_addr: SocketAddr,
    pub database_url: String,
    pub cors_origin: String,
    pub log_level: String,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub signing_key_change_accepted: Option<String>,
    pub proof_deadline_secs: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::from_filename("../../secrets/.env.server.local").ok();

        let host = std::env::var("ZEDR_SERVER_HOST")?;
        let port = std::env::var("ZEDR_SERVER_PORT")?.parse::<u16>()?;
        let server_addr = format!("{}:{}", host, port).parse()?;

        let log_level = std::env::var("ZEDR_LOG_LEVEL")
            .unwrap_or_else(|_| "zedr_control_server=info,tower_http=info".to_string());

        Ok(Self {
            server_addr,
            database_url: std::env::var("DATABASE_URL")?,
            cors_origin: std::env::var("ZEDR_CORS_ORIGIN")?,
            log_level,
            tls_cert_path: PathBuf::from(std::env::var("ZEDR_TLS_CERT_PATH")?),
            tls_key_path: PathBuf::from(std::env::var("ZEDR_TLS_KEY_PATH")?),
            signing_key_change_accepted: std::env::var(crate::signing_key_guard::ACCEPT_CHANGE_ENV).ok(),
            proof_deadline_secs: crate::proofs::deadline_from_env()?,
        })
    }
}
