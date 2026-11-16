use serde::{Deserialize, Serialize, Serializer};
use utoipa::ToSchema;

// Re-export protocol types for API handlers
pub use zedr_protocol::AgentRegistration;

#[derive(Debug, Clone, Deserialize, sqlx::FromRow, ToSchema)]
pub struct Agent {
    pub id: String,
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub architecture: String,
    pub version: String,
    pub ip_address: Option<String>,
    pub last_heartbeat: i64,
    #[sqlx(rename = "status")]
    pub _db_status: String, // Database field, but we calculate status dynamically
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub liveness_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_group: Option<String>,
}

impl Agent {
    /// Calculate agent status based on last_heartbeat timestamp.
    /// Agent is considered offline if last heartbeat is older than 60 seconds (2x heartbeat interval).
    pub fn get_status(&self) -> String {
        let now = chrono::Utc::now().timestamp();
        let heartbeat_timeout = 60; // 2x the default 30 second heartbeat interval
        
        if (now - self.last_heartbeat) > heartbeat_timeout {
            "offline".to_string()
        } else {
            "online".to_string()
        }
    }
}

impl Serialize for Agent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Agent", 11)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("hostname", &self.hostname)?;
        state.serialize_field("platform", &self.platform)?;
        state.serialize_field("os_version", &self.os_version)?;
        state.serialize_field("architecture", &self.architecture)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("ip_address", &self.ip_address)?;
        state.serialize_field("last_heartbeat", &self.last_heartbeat)?;
        state.serialize_field("status", &self.get_status())?; // Dynamic status calculation
        state.serialize_field("created_at", &self.created_at)?;
        state.serialize_field("liveness_state", &self.liveness_state)?;
        if self.user_id.is_some() {
            state.serialize_field("user_id", &self.user_id)?;
        }
        if self.enrollment_token_id.is_some() {
            state.serialize_field("enrollment_token_id", &self.enrollment_token_id)?;
            state.serialize_field("enrollment_group", &self.enrollment_group)?;
        }
        state.end()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct Event {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub event_type: String,
    pub timestamp: i64,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubmission {
    pub agent_id: String,
    pub event_type: String,
    pub data: serde_json::Value,
}
