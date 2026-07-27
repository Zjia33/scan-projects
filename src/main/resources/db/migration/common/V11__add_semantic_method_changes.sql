CREATE TABLE semantic_method_change (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL,
    change_kind VARCHAR(40) NOT NULL,
    method_name VARCHAR(500) NOT NULL,
    base_path VARCHAR(1000),
    target_path VARCHAR(1000),
    base_symbol VARCHAR(1500),
    target_symbol VARCHAR(1500),
    base_start_line INTEGER,
    base_end_line INTEGER,
    target_start_line INTEGER,
    target_end_line INTEGER,
    base_content TEXT NOT NULL,
    target_content TEXT NOT NULL,
    details TEXT NOT NULL,
    CONSTRAINT fk_semantic_method_change_task
        FOREIGN KEY (task_id) REFERENCES audit_task(id) ON DELETE CASCADE
);

CREATE INDEX idx_semantic_method_change_task_kind
    ON semantic_method_change(task_id, change_kind);
CREATE INDEX idx_semantic_method_change_target
    ON semantic_method_change(task_id, target_path, target_start_line);
CREATE INDEX idx_semantic_method_change_base
    ON semantic_method_change(task_id, base_path, base_start_line);
