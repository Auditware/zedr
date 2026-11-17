pub mod agent_auth;
pub mod api;
pub mod attempts;
pub mod audit;
pub mod auth;
#[cfg(test)]
pub mod auth_tests;
pub mod chain;
pub mod config;
pub mod db;
pub mod detections;
pub mod enrollment;
pub mod error;
pub mod hunt;
pub mod incidents;
pub mod liveness;
pub mod mfa;
pub mod proofs;
pub mod server;
pub mod signing;
pub mod signing_key_guard;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tokio::time::{sleep, Duration};

/// Manager for agent heartbeat timeouts using individual timers
pub struct HeartbeatTimeoutManager {
    agent_timers: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    pool: sqlx::SqlitePool,
    agent_events_tx: broadcast::Sender<api::AgentEvent>,
}

impl HeartbeatTimeoutManager {
    pub fn new(pool: sqlx::SqlitePool, agent_events_tx: broadcast::Sender<api::AgentEvent>) -> Self {
        Self {
            agent_timers: Arc::new(Mutex::new(HashMap::new())),
            pool,
            agent_events_tx,
        }
    }
    
    /// Reset timeout for an agent (called when heartbeat received)
    pub async fn reset_timeout(&self, agent_id: String) {
        let mut timers = self.agent_timers.lock().await;
        
        // Cancel existing timer if any
        if let Some(existing_timer) = timers.remove(&agent_id) {
            existing_timer.abort();
        }
        
        // Start new timer
        let agent_id_clone = agent_id.clone();
        let pool = self.pool.clone();
        let tx = self.agent_events_tx.clone();
        
        let timer = tokio::spawn(async move {
            sleep(Duration::from_secs(60)).await; // Exactly 60 seconds
            
            // Mark agent as offline
            if let Err(e) = sqlx::query("UPDATE agents SET status = 'offline' WHERE id = ?")
                .bind(&agent_id_clone)
                .execute(&pool)
                .await
            {
                tracing::error!("Failed to mark agent {} as offline: {}", agent_id_clone, e);
                return;
            }
            
            // Broadcast offline event
            let event = api::AgentEvent {
                agent_id: agent_id_clone.clone(),
                event_type: api::AgentEventType::Offline,
                timestamp: chrono::Utc::now().timestamp(),
            };
            
            if let Err(e) = tx.send(event) {
                tracing::warn!("Failed to broadcast offline event for {}: {}", agent_id_clone, e);
            }
        });
        
        timers.insert(agent_id, timer);
    }
    
    /// Remove agent timer (called when agent is deleted)
    pub async fn remove_agent(&self, agent_id: &str) {
        let mut timers = self.agent_timers.lock().await;
        if let Some(timer) = timers.remove(agent_id) {
            timer.abort();
        }
    }
}
