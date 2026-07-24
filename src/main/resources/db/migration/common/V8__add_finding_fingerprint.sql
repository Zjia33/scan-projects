ALTER TABLE finding ADD COLUMN fingerprint VARCHAR(64) NOT NULL DEFAULT '';
CREATE INDEX idx_finding_fingerprint ON finding(task_id, fingerprint);
