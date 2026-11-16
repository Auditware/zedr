use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    response::Response,
    http::{StatusCode, header, HeaderMap},
};
use serde::Deserialize;
use std::path::PathBuf;
use tower_http::services::ServeFile;
use uuid::Uuid;
use chrono;
use serde_json;

use crate::api::AppState;
use crate::enrollment::{self, Credential};
use crate::error::AppError;
use crate::incidents;
use crate::signing::SigningService;

fn binaries_dir() -> Result<PathBuf, AppError> {
    std::env::var("ZEDR_BINARIES_DIR")
        .map(PathBuf::from)
        .map_err(|_| AppError::Config("ZEDR_BINARIES_DIR environment variable must be set".to_string()))
}

fn serve_binary(binary_path: &PathBuf, binary_name: &str) -> Result<Response, AppError> {
    let template_binary = std::fs::read(binary_path)
        .map_err(|e| AppError::InternalError(format!("Failed to create signature: {}", e)))?;
    
    let server_url = std::env::var("ZEDR_SERVER_URL")
        .map_err(|_| AppError::Config("ZEDR_SERVER_URL environment variable must be set".to_string()))?;
    
    let binary_with_signature = SigningService::from_env()?.seal_agent_binary(&template_binary, &server_url)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", binary_name))
        .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .body(binary_with_signature.into())
        .unwrap())
}

#[derive(Deserialize)]
pub struct BinaryQuery {
    key: Option<String>,
}

pub fn current_agent_version() -> String {
    std::env::var("ZEDR_AGENT_VERSION").unwrap_or_else(|_| "0.1.0".to_string())
}

/// What an installer asked for, after its credential was accepted
struct Download {
    presented: String,
    credential: Credential,
    directory: PathBuf,
    extension: &'static str,
}

async fn authorize_download(state: &AppState, platform: &str, query_key: Option<&str>, headers: &HeaderMap) -> Result<Download, AppError> {
    let presented = enrollment::presented_key(headers, query_key)
        .ok_or_else(|| AppError::BadRequest("Missing enrollment key".to_string()))?;

    let now = chrono::Utc::now().timestamp();
    let Some(credential) = enrollment::usable_credential(&state.pool, &presented, now).await? else {
        record_refused_fleet_download(state, &presented, platform, now).await?;
        return Err(AppError::Unauthorized);
    };

    if matches!(credential, Credential::InstallKey { downloaded: true, .. }) {
        return Err(AppError::Unauthorized);
    }

    let (os, arch) = parse_platform(platform)?;

    let extension = match os.as_str() {
        "windows" => ".exe",
        "linux" | "macos" => "",
        _ => return Err(AppError::NotFound),
    };

    if !matches!(arch.as_str(), "x64" | "arm64") {
        return Err(AppError::NotFound);
    }

    let directory = binaries_dir()?.join(format!("v{}/{}/{}", current_agent_version(), os, arch));
    Ok(Download { presented, credential, directory, extension })
}

pub async fn serve_authenticated_binary(
    State(state): State<AppState>,
    Path(platform): Path<String>,
    Query(query): Query<BinaryQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Download { presented, credential, directory, extension } = authorize_download(&state, &platform, query.key.as_deref(), &headers).await?;

    let version = current_agent_version();
    let binary_name = format!("zedr-agent{}", extension);
    let binary_path = directory.join(&binary_name);

    if !binary_path.exists() {
        return Err(AppError::Config(format!("Agent binary not found for platform: {} (version: {})", platform, version)));
    }

    let download = match &credential {
        Credential::InstallKey { created_by, .. } => serde_json::json!({
            "install_key": presented.chars().take(12).collect::<String>(),
            "requesting_user": created_by,
            "description": "Agent installation binary downloaded via install key",
        }),
        Credential::FleetToken(token) => serde_json::json!({
            "enrollment_token_id": token.id,
            "enrollment_group": token.label,
            "description": "Agent installation binary downloaded via fleet enrollment token",
        }),
    };

    if let Err(e) = create_installation_event(&state, download, &platform, &version).await {
        tracing::error!("Failed to create server-initiated installation event: {}", e);
    }

    if let Credential::InstallKey { id, .. } = &credential {
        let _ = mark_key_as_used(&state, id).await;
    }

    serve_binary(&binary_path, &binary_name)
}

/// The prover that belongs to the agent of the same platform and version, for the credential that downloads that agent.
/// An install key stays usable after it, the agent download is what uses the key up, so an installer asks for the prover first.
/// A deployment that built no prover for the platform answers 404 and its endpoints seal without proving
pub async fn serve_authenticated_prover(
    State(state): State<AppState>,
    Path(platform): Path<String>,
    Query(query): Query<BinaryQuery>,
    request: Request,
) -> Result<Response, AppError> {
    let download = authorize_download(&state, &platform, query.key.as_deref(), request.headers()).await?;
    let prover_path = download.directory.join(format!("zedr-prover{}", download.extension));

    if !prover_path.is_file() {
        return Err(AppError::NotFound);
    }

    let response = ServeFile::new(&prover_path)
        .try_call(request)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to read the prover: {}", e)))?;
    Ok(response.map(Body::new))
}

async fn record_refused_fleet_download(state: &AppState, presented: &str, platform: &str, now: i64) -> Result<(), AppError> {
    if !enrollment::is_fleet_token(presented) {
        return Ok(());
    }

    let mut conn = state.pool.acquire().await?;
    let refused = enrollment::refused_fleet_token(&mut conn, presented, now).await?;
    drop(conn);

    if let Some((token, reason)) = refused {
        incidents::record_event(
            &state.pool,
            &state.system_events_tx,
            None,
            "enrollment_rejected",
            serde_json::json!({
                "stage": "download",
                "platform": platform,
                "enrollment_token_id": token.id,
                "enrollment_group": token.label,
                "reason": reason,
            }),
        )
        .await?;
    }

    Ok(())
}

fn parse_platform(platform: &str) -> Result<(String, String), AppError> {
    let parts: Vec<&str> = platform.split('-').collect();
    if parts.len() != 2 {
        return Err(AppError::BadRequest("Invalid platform format. Expected: os-arch".to_string()));
    }
    
    Ok((parts[0].to_string(), parts[1].to_string()))
}

async fn mark_key_as_used(state: &AppState, key_id: &str) -> Result<(), AppError> {
    let now = chrono::Utc::now().timestamp();
    
    sqlx::query(
        "UPDATE install_keys SET used_at = ? WHERE id = ?"
    )
    .bind(now)
    .bind(key_id)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::InternalError(format!("Failed to update install key: {}", e)))?;
    
    Ok(())
}

async fn create_installation_event(state: &AppState, mut download: serde_json::Value, platform: &str, version: &str) -> Result<(), AppError> {
    let event_id = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp();

    if let Some(fields) = download.as_object_mut() {
        fields.insert("timestamp".to_string(), serde_json::json!(timestamp));
        fields.insert("version".to_string(), serde_json::json!(version));
        fields.insert("signature_verified".to_string(), serde_json::json!(true));
        fields.insert("platform".to_string(), serde_json::json!(platform));
        fields.insert("status".to_string(), serde_json::json!("installation_requested"));
        fields.insert("source".to_string(), serde_json::json!("server"));
    }

    sqlx::query(
        "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at)
         VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(event_id)
    .bind::<Option<String>>(None)
    .bind("install")
    .bind(timestamp)
    .bind(download.to_string())
    .bind(timestamp)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::InternalError(format!("Failed to create installation event: {}", e)))?;

    Ok(())
}

#[derive(Deserialize)]
pub struct UpgradeQuery {
    key: String,
}

pub async fn serve_upgrade_binary(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(query): Query<UpgradeQuery>,
) -> Result<Response, AppError> {
    
    let version = &query.key;
    
    let agent = sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, platform, architecture FROM agents WHERE id = ?"
    )
    .bind(&agent_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::InternalError(format!("Failed to query agent: {}", e)))?
    .ok_or(AppError::Unauthorized)?;
    
    let (_agent_id, os, arch) = agent;
    
    let arch_dir = match arch.as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        other => other,
    };
    
    let upgrade_exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM upgrade_commands WHERE agent_id = ? AND target_version = ? AND status = 'pending'"
    )
    .bind(&agent_id)
    .bind(version)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::InternalError(format!("Failed to verify upgrade command: {}", e)))?;
    
    if upgrade_exists == 0 {
        return Err(AppError::Unauthorized);
    }
    
    let extension = match os.as_str() {
        "windows" => ".exe",
        "linux" | "macos" => "",
        _ => return Err(AppError::NotFound),
    };
    
    let version_dir = if version.starts_with('v') { version.to_string() } else { format!("v{}", version) };
    let binary_path = binaries_dir()?.join(format!("{}/{}/{}/zedr-agent{}", version_dir, os, arch_dir, extension));
    
    if !binary_path.exists() {
        return Err(AppError::Config(format!("Agent binary not found for version: {}", version)));
    }
    
    let binary_name = format!("zedr-agent{}", extension);
    serve_binary(&binary_path, &binary_name)
}
