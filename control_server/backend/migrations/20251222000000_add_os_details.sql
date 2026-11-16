-- Add OS version and architecture columns to agents table
ALTER TABLE agents ADD COLUMN os_version TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN architecture TEXT NOT NULL DEFAULT '';
