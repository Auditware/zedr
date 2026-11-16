ALTER TABLE upgrade_commands ADD COLUMN signature BLOB;
ALTER TABLE upgrade_commands ADD COLUMN issued_at INTEGER;
ALTER TABLE upgrade_commands ADD COLUMN nonce TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_upgrade_commands_nonce ON upgrade_commands(nonce) WHERE nonce IS NOT NULL;
