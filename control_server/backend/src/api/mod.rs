use axum::{extract::DefaultBodyLimit, http::StatusCode, routing::{any, get, post}, Router, Json};
use ipnet::IpNet;
use sqlx::SqlitePool;
use tokio::sync::broadcast;
use tower_http::services::{ServeDir, ServeFile};
use utoipa::{OpenApi, ToSchema};
use std::path::PathBuf;
use std::sync::Arc;
use crate::proofs::{ReceiptVerifier, Risc0Verifier};
use crate::signing::SigningService;

pub mod admin;
pub mod auth;
pub mod binaries;
pub mod health;
pub mod ingestion;
pub mod install;
pub mod middleware;

use health::HealthResponse;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub agent_events_tx: broadcast::Sender<AgentEvent>,
    pub system_events_tx: broadcast::Sender<SystemEventBroadcast>,
    pub timeout_manager: Option<Arc<crate::HeartbeatTimeoutManager>>,
    pub signing_service: Arc<SigningService>,
    pub operator_allowlist: Arc<Vec<IpNet>>,
    pub receipt_verifier: Arc<dyn ReceiptVerifier>,
}

#[derive(Default)]
pub struct RouterOptions {
    pub operator_allowlist: Vec<IpNet>,
    pub frontend_dist: Option<PathBuf>,
    /// Checks proof receipts in place of the one built from ZEDR_GUEST_IMAGE_IDS
    pub receipt_verifier: Option<Arc<dyn ReceiptVerifier>>,
}

impl RouterOptions {
    pub fn from_env() -> Self {
        let operator_allowlist = std::env::var("ZEDR_ADMIN_ALLOWED_CIDRS")
            .map(|raw| middleware::parse_operator_allowlist(&raw).expect("ZEDR_ADMIN_ALLOWED_CIDRS must be a comma-separated list of CIDRs"))
            .unwrap_or_default();

        Self {
            operator_allowlist,
            frontend_dist: std::env::var("ZEDR_FRONTEND_DIST").ok().map(PathBuf::from),
            receipt_verifier: None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, ToSchema)]
pub struct AgentEvent {
    pub agent_id: String,
    pub event_type: AgentEventType,
    pub timestamp: i64,
}

#[derive(Clone, Debug, serde::Serialize, ToSchema)]
pub enum AgentEventType {
    Registered,
    Heartbeat,
    Offline,
}

#[derive(Clone, Debug, serde::Serialize, ToSchema)]
pub struct SystemEventBroadcast {
    pub id: String,
    pub agent_id: String,
    pub event_type: String,
    pub timestamp: i64,
    pub data: String,
    pub received_at: i64,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "zedr Control Server API",
        version = "0.1.0",
        description = "API for managing zedr EDR agents"
    ),
    servers(
        (url = "http://localhost:7770", description = "Local development server")
    ),
    paths(
        health::health_check,
        ingestion::register::register_agent,
        ingestion::events::ingest_events,
        ingestion::windows::ingest_window,
        ingestion::proofs::submit_proof,
        admin::agents::list_agents,
        admin::agents::get_agent,
        admin::agents::stream_agents,
        admin::chain::agent_chain,
        admin::chain::agent_window,
        admin::chain::ruleset,
        admin::events::list_events,
        admin::events::event_stats,
        admin::events::event_histogram,
        admin::hunt::hunt,
        admin::hunt::hunt_fields,
        admin::incidents::list_incidents,
        admin::incidents::close_incident,
        admin::installers::generate_install_key,
        admin::enrollment_tokens::create_enrollment_token,
        admin::enrollment_tokens::list_enrollment_tokens,
        admin::enrollment_tokens::revoke_enrollment_token,
        admin::api_keys::create_api_key,
        admin::api_keys::list_api_keys,
        admin::api_keys::revoke_api_key,
        admin::users::list_users,
        admin::users::create_user,
        admin::users::delete_user,
        admin::users::update_user,
        admin::users::reset_password,
        admin::users::reset_mfa,
        admin::users::sign_out,
        admin::users::impersonate,
        admin::audit::list_audit,
        auth::login,
        auth::login_mfa,
        auth::mfa_status,
        auth::mfa_setup,
        auth::mfa_enable,
        auth::mfa_disable,
    ),
    components(
        schemas(
            zedr_protocol::AgentRegistration,
            zedr_protocol::AgentRegistrationResponse,
            zedr_protocol::DetectionEvent,
            zedr_protocol::SystemEvent,
            zedr_protocol::SealedWindow,
            zedr_protocol::SealedWindowHeader,
            zedr_protocol::SealedEvent,
            zedr_protocol::Release,
            zedr_protocol::Opening,
            zedr_protocol::SealedWindowAck,
            zedr_protocol::ChainPosition,
            zedr_protocol::ProofSubmission,
            zedr_protocol::ProofAck,
            crate::db::models::Agent,
            crate::db::models::Event,
            crate::incidents::Incident,
            crate::hunt::HuntResult,
            crate::hunt::HuntRow,
            crate::hunt::HuntEndpoint,
            crate::hunt::HuntEntity,
            admin::hunt::HuntRequest,
            admin::hunt::HuntQueryError,
            admin::incidents::IncidentsQuery,
            crate::api::AgentEvent,
            HealthResponse,
            admin::agents::ListQuery,
            admin::chain::ChainQuery,
            admin::chain::ChainView,
            admin::chain::ChainTotals,
            admin::chain::WindowSummary,
            admin::chain::WindowView,
            admin::chain::SealedEventView,
            admin::chain::ReleaseView,
            admin::chain::RulesetView,
            admin::chain::RuleView,
            admin::events::EventsQuery,
            admin::events::EventStats,
            admin::events::HistogramQuery,
            admin::events::EventHistogram,
            admin::events::EventSeries,
            admin::installers::InstallKeyResponse,
            admin::enrollment_tokens::CreateEnrollmentTokenRequest,
            admin::enrollment_tokens::EnrollmentTokenCreated,
            admin::enrollment_tokens::EnrollmentToken,
            admin::enrollment_tokens::EnrollmentTokensResponse,
            admin::api_keys::CreateApiKeyRequest,
            admin::api_keys::ApiKeyResponse,
            admin::api_keys::ApiKeyListItem,
            auth::LoginRequest,
            auth::LoginResponse,
            auth::MfaLoginRequest,
            auth::MfaCodeRequest,
            auth::MfaStatusResponse,
            auth::MfaSetupResponse,
            auth::MfaEnableResponse,
            admin::users::UserSummary,
            admin::users::CreateUserRequest,
            admin::users::UpdateUserRequest,
            admin::users::ResetPasswordRequest,
            admin::users::ImpersonationResponse,
            admin::audit::AuditResponse,
            crate::audit::AuditEntry,
        )
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "agents", description = "Agent registration and heartbeat"),
        (name = "admin", description = "Admin API for management"),
        (name = "auth", description = "Authentication endpoints"),
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer
                    )
                )
            )
        }
    }
}

pub fn create_router(pool: SqlitePool) -> Router {
    create_router_with_options(pool, RouterOptions::from_env())
}

pub fn create_router_with_options(pool: SqlitePool, options: RouterOptions) -> Router {
    let (agent_events_tx, _) = broadcast::channel(100);
    let (system_events_tx, _) = broadcast::channel(1000);
    build_router(pool, agent_events_tx, system_events_tx, None, options)
}

pub fn create_router_with_state_and_timeout_manager(
    pool: SqlitePool,
    agent_events_tx: broadcast::Sender<AgentEvent>,
    system_events_tx: broadcast::Sender<SystemEventBroadcast>,
    timeout_manager: Arc<crate::HeartbeatTimeoutManager>,
) -> Router {
    build_router(pool, agent_events_tx, system_events_tx, Some(timeout_manager), RouterOptions::from_env())
}

pub fn create_router_with_state(
    pool: SqlitePool,
    agent_events_tx: broadcast::Sender<AgentEvent>,
    system_events_tx: broadcast::Sender<SystemEventBroadcast>,
) -> Router {
    build_router(pool, agent_events_tx, system_events_tx, None, RouterOptions::from_env())
}

fn build_router(
    pool: SqlitePool,
    agent_events_tx: broadcast::Sender<AgentEvent>,
    system_events_tx: broadcast::Sender<SystemEventBroadcast>,
    timeout_manager: Option<Arc<crate::HeartbeatTimeoutManager>>,
    options: RouterOptions,
) -> Router {
    let signing_service = Arc::new(SigningService::from_env().expect("Failed to initialize signing service"));
    let receipt_verifier = options.receipt_verifier.unwrap_or_else(|| {
        let verifier = Risc0Verifier::from_env().expect("ZEDR_GUEST_IMAGE_IDS must be a comma-separated list of 64 hex character image IDs");
        if verifier.image_ids().is_empty() {
            tracing::warn!("ZEDR_GUEST_IMAGE_IDS names no rule program, no proof can be accepted");
        }
        Arc::new(verifier)
    });

    let state = AppState {
        pool,
        agent_events_tx,
        system_events_tx,
        timeout_manager,
        signing_service,
        operator_allowlist: Arc::new(options.operator_allowlist),
        receipt_verifier,
    };

    create_router_with_appstate(state, options.frontend_dist)
}

fn create_router_with_appstate(state: AppState, frontend_dist: Option<PathBuf>) -> Router {
    let protected = Router::new()
        .route("/api/admin/agents", get(admin::agents::list_agents))
        .route("/api/admin/agents/:id", get(admin::agents::get_agent))
        .route("/api/admin/agents/:id/chain", get(admin::chain::agent_chain))
        .route("/api/admin/agents/:id/windows/:window", get(admin::chain::agent_window))
        .route("/api/admin/ruleset", get(admin::chain::ruleset))
        .route("/api/admin/events", get(admin::events::list_events))
        .route("/api/admin/events/stats", get(admin::events::event_stats))
        .route("/api/admin/events/histogram", get(admin::events::event_histogram))
        .route("/api/admin/hunt", post(admin::hunt::hunt))
        .route("/api/admin/hunt/fields", get(admin::hunt::hunt_fields))
        .route("/api/admin/incidents", get(admin::incidents::list_incidents))
        .route("/api/admin/incidents/:id/close", post(admin::incidents::close_incident))
        .route("/api/admin/installers", get(admin::installers::list_install_keys))
        .route("/api/admin/installers/generate", post(admin::installers::generate_install_key))
        .route(
            "/api/admin/enrollment-tokens",
            get(admin::enrollment_tokens::list_enrollment_tokens).post(admin::enrollment_tokens::create_enrollment_token),
        )
        .route(
            "/api/admin/enrollment-tokens/:id",
            axum::routing::delete(admin::enrollment_tokens::revoke_enrollment_token),
        )
        .route("/api/admin/upgrades", post(admin::upgrades::issue_upgrade))
        .route("/api/admin/upgrades", get(admin::upgrades::list_upgrades))
        .route("/api/admin/api-keys", post(admin::api_keys::create_api_key))
        .route("/api/admin/api-keys", get(admin::api_keys::list_api_keys))
        .route("/api/admin/api-keys/:id", axum::routing::delete(admin::api_keys::revoke_api_key))
        .route("/api/admin/users", get(admin::users::list_users).post(admin::users::create_user))
        .route(
            "/api/admin/users/:id",
            axum::routing::delete(admin::users::delete_user).patch(admin::users::update_user),
        )
        .route("/api/admin/users/:id/password", post(admin::users::reset_password))
        .route("/api/admin/users/:id/mfa/reset", post(admin::users::reset_mfa))
        .route("/api/admin/users/:id/sign-out", post(admin::users::sign_out))
        .route("/api/admin/users/:id/impersonate", post(admin::users::impersonate))
        .route("/api/admin/audit", get(admin::audit::list_audit))
        .route("/api/auth/mfa", get(auth::mfa_status))
        .route("/api/auth/mfa/setup", post(auth::mfa_setup))
        .route("/api/auth/mfa/enable", post(auth::mfa_enable))
        .route("/api/auth/mfa/disable", post(auth::mfa_disable))
        .layer(axum::middleware::from_fn_with_state(state.clone(), self::middleware::auth_middleware));

    let router = Router::new()
        .route("/api-docs/openapi.json", get(|| async { Json(ApiDoc::openapi()) }))
        .route("/api-docs/swagger-ui", get(swagger_ui))
        .route("/health", get(health::health_check))
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/api/*unmatched", any(|| async { StatusCode::NOT_FOUND }))
        .route("/api/agents/register", post(ingestion::register::register_agent))
        .route(
            "/api/events",
            post(ingestion::events::ingest_events).layer(DefaultBodyLimit::max(zedr_protocol::MAX_EVENT_BATCH_BYTES)),
        )
        .route(
            "/api/windows",
            post(ingestion::windows::ingest_window).layer(DefaultBodyLimit::max(ingestion::windows::MAX_WINDOW_BYTES)),
        )
        .route("/api/proofs", post(ingestion::proofs::submit_proof))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/login/mfa", post(auth::login_mfa))
        .route("/api/admin/agents/stream", get(admin::agents::stream_agents))
        .route("/api/admin/events/stream", get(admin::events::stream_events))
        .route("/install.ps1", get(install::serve_windows_installer))
        .route("/install.sh", get(install::serve_unix_installer))
        .route("/api/installers/binaries/:platform", get(binaries::serve_authenticated_binary))
        .route("/api/agents/:agent_id/upgrade-binary", get(binaries::serve_upgrade_binary))
        .merge(protected);

    let router = match frontend_dist {
        Some(dist) => router.fallback_service(
            ServeDir::new(&dist).fallback(ServeFile::new(dist.join("index.html"))),
        ),
        None => router,
    };

    router
        .layer(axum::middleware::from_fn_with_state(state.clone(), self::middleware::operator_allowlist))
        .with_state(state)
}

async fn swagger_ui() -> axum::response::Html<String> {
    axum::response::Html(format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Control Server API</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({{
            url: '/api-docs/openapi.json',
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
            layout: 'BaseLayout'
        }})
    </script>
</body>
</html>
"#))
}
