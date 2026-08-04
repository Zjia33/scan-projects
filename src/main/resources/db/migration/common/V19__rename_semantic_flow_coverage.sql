ALTER TABLE security_flow RENAME COLUMN resolved_edges TO confirmed_relation_edges;
ALTER TABLE security_flow RENAME COLUMN unresolved_edges TO local_semantic_gaps;
