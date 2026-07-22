CREATE INDEX IF NOT EXISTS idx_audit_task_project_id ON audit_task(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_task_created_at ON audit_task(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_code_chunk_task_id ON code_chunk(task_id);
CREATE INDEX IF NOT EXISTS idx_finding_task_id ON finding(task_id);
CREATE INDEX IF NOT EXISTS idx_finding_task_severity ON finding(task_id, severity);
