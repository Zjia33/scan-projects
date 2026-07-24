ALTER TABLE audit_project ADD COLUMN source_type VARCHAR(20) NOT NULL DEFAULT 'ZIP';
ALTER TABLE audit_project ADD COLUMN repository_url VARCHAR(2000);
ALTER TABLE audit_project ADD COLUMN default_branch VARCHAR(500);

ALTER TABLE audit_task ADD COLUMN scan_mode VARCHAR(30) NOT NULL DEFAULT 'FULL';
ALTER TABLE audit_task ADD COLUMN base_commit_sha VARCHAR(64);
ALTER TABLE audit_task ADD COLUMN target_commit_sha VARCHAR(64);
ALTER TABLE audit_task ADD COLUMN merge_base_sha VARCHAR(64);
ALTER TABLE audit_task ADD COLUMN change_summary TEXT;

ALTER TABLE code_chunk ADD COLUMN change_type VARCHAR(30) NOT NULL DEFAULT 'UNCHANGED';
ALTER TABLE code_chunk ADD COLUMN analysis_scope VARCHAR(30) NOT NULL DEFAULT 'FULL';
ALTER TABLE code_chunk ADD COLUMN base_content TEXT NOT NULL DEFAULT '';

ALTER TABLE finding ADD COLUMN delta_status VARCHAR(30) NOT NULL DEFAULT 'BASELINE';

CREATE TABLE git_file_change (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL,
    old_path VARCHAR(1000),
    new_path VARCHAR(1000),
    change_type VARCHAR(30) NOT NULL,
    additions INTEGER NOT NULL,
    deletions INTEGER NOT NULL,
    old_ranges TEXT NOT NULL,
    new_ranges TEXT NOT NULL,
    context_text TEXT NOT NULL,
    configuration_change BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_git_file_change_task FOREIGN KEY (task_id) REFERENCES audit_task(id) ON DELETE CASCADE
);

CREATE INDEX idx_git_file_change_task ON git_file_change(task_id);
CREATE INDEX idx_git_file_change_target_path ON git_file_change(task_id, new_path);
