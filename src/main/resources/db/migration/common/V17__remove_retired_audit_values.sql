DELETE FROM finding
WHERE type NOT IN ('AUTHORIZATION', 'SQL_INJECTION', 'UNAUTHORIZED_DISCLOSURE',
                   'STORED_XSS', 'VALIDATION_BYPASS');

DELETE FROM audit_hypothesis
WHERE type NOT IN ('AUTHORIZATION', 'SQL_INJECTION', 'UNAUTHORIZED_DISCLOSURE',
                   'STORED_XSS', 'VALIDATION_BYPASS');

DELETE FROM security_flow
WHERE type NOT IN ('AUTHORIZATION', 'SQL_INJECTION', 'UNAUTHORIZED_DISCLOSURE',
                   'STORED_XSS', 'VALIDATION_BYPASS');

DELETE FROM agent_event
WHERE agent_type NOT IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                         'STORED_XSS', 'VALIDATION_BYPASS', 'CRITIC', 'REPORT');

DELETE FROM agent_run
WHERE agent_type NOT IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                         'STORED_XSS', 'VALIDATION_BYPASS', 'CRITIC', 'REPORT');

UPDATE audit_task
SET status = 'FAILED',
    current_stage = '任务使用已移除的执行阶段，请重新发起增量审计',
    error_message = '当前版本不再支持旧执行阶段',
    completed_at = CURRENT_TIMESTAMP
WHERE status NOT IN ('UPLOADED', 'MATERIALIZING', 'DIFFING', 'INVENTORY', 'INDEXING',
                     'RECON', 'AGENT_RECON', 'PLANNING', 'ANALYSIS', 'CRITIC_REVIEW',
                     'RESULT_VALIDATION', 'REPORTING', 'COMPLETED', 'FAILED', 'CANCELLED');

UPDATE code_chunk
SET analysis_scope = 'CONTEXT'
WHERE analysis_scope NOT IN ('CHANGED', 'IMPACTED', 'CONTEXT');

UPDATE finding
SET delta_status = 'NEW'
WHERE delta_status NOT IN ('NEW', 'PERSISTING');

ALTER TABLE finding ADD CONSTRAINT chk_finding_current_type
    CHECK (type IN ('AUTHORIZATION', 'SQL_INJECTION', 'UNAUTHORIZED_DISCLOSURE',
                    'STORED_XSS', 'VALIDATION_BYPASS'));

ALTER TABLE audit_hypothesis ADD CONSTRAINT chk_hypothesis_current_type
    CHECK (type IN ('AUTHORIZATION', 'SQL_INJECTION', 'UNAUTHORIZED_DISCLOSURE',
                    'STORED_XSS', 'VALIDATION_BYPASS'));

ALTER TABLE security_flow ADD CONSTRAINT chk_security_flow_current_type
    CHECK (type IN ('AUTHORIZATION', 'SQL_INJECTION', 'UNAUTHORIZED_DISCLOSURE',
                    'STORED_XSS', 'VALIDATION_BYPASS'));

ALTER TABLE agent_run ADD CONSTRAINT chk_agent_run_current_type
    CHECK (agent_type IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                          'STORED_XSS', 'VALIDATION_BYPASS', 'CRITIC', 'REPORT'));

ALTER TABLE agent_event ADD CONSTRAINT chk_agent_event_current_type
    CHECK (agent_type IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                          'STORED_XSS', 'VALIDATION_BYPASS', 'CRITIC', 'REPORT'));

ALTER TABLE audit_task ADD CONSTRAINT chk_audit_task_current_status
    CHECK (status IN ('UPLOADED', 'MATERIALIZING', 'DIFFING', 'INVENTORY', 'INDEXING',
                      'RECON', 'AGENT_RECON', 'PLANNING', 'ANALYSIS', 'CRITIC_REVIEW',
                      'RESULT_VALIDATION', 'REPORTING', 'COMPLETED', 'FAILED', 'CANCELLED'));

ALTER TABLE code_chunk ADD CONSTRAINT chk_code_chunk_current_scope
    CHECK (analysis_scope IN ('CHANGED', 'IMPACTED', 'CONTEXT'));

ALTER TABLE finding ADD CONSTRAINT chk_finding_current_delta
    CHECK (delta_status IN ('NEW', 'PERSISTING'));
