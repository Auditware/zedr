-- Add termination reason and executed commands list for audit trail
-- Sessions terminate via timeout or manual termination, closing an "investigation"

ALTER TABLE shell_sessions ADD COLUMN termination_reason TEXT;
ALTER TABLE shell_sessions ADD COLUMN executed_commands TEXT;
