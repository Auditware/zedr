use axum::http::header;
use axum_server::tls_rustls::RustlsConfig;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::proofs::ReceiptVerifier;
use crate::signing::SigningService;
use crate::{api, config, db, signing_key_guard, HeartbeatTimeoutManager};

/// Runs the control server until it is told to stop. A verifier given here checks the proof receipts in place of
/// the one built from ZEDR_GUEST_IMAGE_IDS, which only the test tenant does
pub async fn run(receipt_verifier: Option<Arc<dyn ReceiptVerifier>>) -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::from_env()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::new(&config.log_level),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = db::create_pool(&config.database_url).await?;

    crate::auth::seed_admin_user(&pool).await?;

    let signing_key_outcome = signing_key_guard::enforce(
        &pool,
        &SigningService::from_env()?,
        config.signing_key_change_accepted.as_deref(),
    )
    .await?;
    if let signing_key_guard::Outcome::Changed { enrolled_agents } = signing_key_outcome {
        tracing::warn!(
            "Signing key changed. Enrolled agents that still trust the previous key and must be reinstalled: {}",
            enrolled_agents
        );
    }

    let cors = CorsLayer::new()
        .allow_origin(config.cors_origin.parse::<header::HeaderValue>()?)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .expose_headers([header::RETRY_AFTER]);

    let (agent_events_tx, _) = tokio::sync::broadcast::channel(100);
    let (system_events_tx, _) = tokio::sync::broadcast::channel(1000);
    
    // Create heartbeat timeout manager
    let timeout_manager = Arc::new(HeartbeatTimeoutManager::new(
        pool.clone(),
        agent_events_tx.clone()
    ));
    
    crate::liveness::spawn_sweeper(pool.clone(), system_events_tx.clone());
    crate::proofs::spawn_sweeper(pool.clone(), system_events_tx.clone(), config.proof_deadline_secs);

    let options = api::RouterOptions { receipt_verifier, ..api::RouterOptions::from_env() };
    let app = api::create_router_with_state_and_timeout_manager(pool, agent_events_tx, system_events_tx, timeout_manager, options)
        .layer(cors)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    tracing::info!("zedr Control Server listening on {}", config.server_addr);

    let cert_pem = tokio::fs::read(&config.tls_cert_path).await?;
    let key_pem = tokio::fs::read(&config.tls_key_path).await?;
    
    // Parse certificates
    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()?;
    
    // Parse private key
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "No private key found"))?;
    
    // Build ServerConfig with only HTTP/1.1 in ALPN (no h2)
    let mut rustls_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    rustls_server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    
    let tls_config = RustlsConfig::from_config(Arc::new(rustls_server_config));

    let handle = axum_server::Handle::new();
    tokio::spawn(drain_on_shutdown_signal(handle.clone()));

    axum_server::bind_rustls(config.server_addr, tls_config)
        .handle(handle)
        .serve(app)
        .await?;

    Ok(())
}

async fn drain_on_shutdown_signal(handle: axum_server::Handle<std::net::SocketAddr>) {
    let interrupt = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to listen for SIGTERM");
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }

    tracing::info!("Shutdown signal received, draining connections");
    handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
}
