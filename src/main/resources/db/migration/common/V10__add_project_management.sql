ALTER TABLE audit_project ADD COLUMN description VARCHAR(1000) NOT NULL DEFAULT '';
ALTER TABLE audit_project ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE audit_project ADD COLUMN archived_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX idx_audit_project_archived_at ON audit_project(archived_at);
