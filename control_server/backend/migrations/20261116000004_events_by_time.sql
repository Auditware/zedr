CREATE INDEX idx_events_ts_type ON events(timestamp, event_type);
CREATE INDEX idx_audit_log_ts ON audit_log(timestamp);
