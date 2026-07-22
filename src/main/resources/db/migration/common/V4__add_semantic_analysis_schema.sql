CREATE TABLE semantic_symbol (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL,
    chunk_id BIGINT,
    kind VARCHAR(40) NOT NULL,
    qualified_name VARCHAR(1500) NOT NULL,
    simple_name VARCHAR(500) NOT NULL,
    owner_name VARCHAR(1000),
    signature TEXT NOT NULL,
    return_type VARCHAR(1000),
    parameter_types TEXT NOT NULL,
    file_path VARCHAR(1000) NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    endpoint VARCHAR(500),
    annotations TEXT NOT NULL,
    details TEXT NOT NULL,
    CONSTRAINT fk_semantic_symbol_task FOREIGN KEY (task_id) REFERENCES audit_task(id) ON DELETE CASCADE,
    CONSTRAINT fk_semantic_symbol_chunk FOREIGN KEY (chunk_id) REFERENCES code_chunk(id) ON DELETE SET NULL
);

CREATE TABLE semantic_call_edge (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL,
    caller_symbol_id UUID NOT NULL,
    callee_symbol_id UUID,
    caller_chunk_id BIGINT,
    callee_chunk_id BIGINT,
    call_site_line INTEGER NOT NULL,
    called_name VARCHAR(500) NOT NULL,
    expression TEXT NOT NULL,
    edge_type VARCHAR(40) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    resolution_reason TEXT NOT NULL,
    argument_mapping TEXT NOT NULL,
    CONSTRAINT fk_semantic_edge_task FOREIGN KEY (task_id) REFERENCES audit_task(id) ON DELETE CASCADE,
    CONSTRAINT fk_semantic_edge_caller FOREIGN KEY (caller_symbol_id) REFERENCES semantic_symbol(id) ON DELETE CASCADE,
    CONSTRAINT fk_semantic_edge_callee FOREIGN KEY (callee_symbol_id) REFERENCES semantic_symbol(id) ON DELETE CASCADE,
    CONSTRAINT fk_semantic_edge_caller_chunk FOREIGN KEY (caller_chunk_id) REFERENCES code_chunk(id) ON DELETE SET NULL,
    CONSTRAINT fk_semantic_edge_callee_chunk FOREIGN KEY (callee_chunk_id) REFERENCES code_chunk(id) ON DELETE SET NULL
);

CREATE TABLE security_flow (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL,
    type VARCHAR(50) NOT NULL,
    source_symbol_id UUID,
    sink_symbol_id UUID,
    primary_chunk_id BIGINT NOT NULL,
    source_description TEXT NOT NULL,
    sink_description TEXT NOT NULL,
    guard_summary TEXT NOT NULL,
    path_text TEXT NOT NULL,
    evidence_chunk_ids TEXT NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    resolved_edges INTEGER NOT NULL,
    unresolved_edges INTEGER NOT NULL,
    CONSTRAINT fk_security_flow_task FOREIGN KEY (task_id) REFERENCES audit_task(id) ON DELETE CASCADE,
    CONSTRAINT fk_security_flow_source FOREIGN KEY (source_symbol_id) REFERENCES semantic_symbol(id) ON DELETE SET NULL,
    CONSTRAINT fk_security_flow_sink FOREIGN KEY (sink_symbol_id) REFERENCES semantic_symbol(id) ON DELETE SET NULL,
    CONSTRAINT fk_security_flow_chunk FOREIGN KEY (primary_chunk_id) REFERENCES code_chunk(id) ON DELETE CASCADE
);

CREATE INDEX idx_semantic_symbol_task ON semantic_symbol(task_id);
CREATE INDEX idx_semantic_symbol_qualified ON semantic_symbol(task_id, qualified_name);
CREATE INDEX idx_semantic_edge_caller ON semantic_call_edge(task_id, caller_symbol_id);
CREATE INDEX idx_semantic_edge_callee ON semantic_call_edge(task_id, callee_symbol_id);
CREATE INDEX idx_security_flow_task_type ON security_flow(task_id, type);
CREATE INDEX idx_security_flow_primary_chunk ON security_flow(task_id, primary_chunk_id);
