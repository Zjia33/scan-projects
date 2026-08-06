ALTER TABLE agent_run DROP CONSTRAINT chk_agent_run_current_type;
ALTER TABLE agent_event DROP CONSTRAINT chk_agent_event_current_type;
ALTER TABLE audit_task DROP CONSTRAINT chk_audit_task_current_status;

DELETE FROM agent_event WHERE agent_type = 'CRITIC';
DELETE FROM agent_run WHERE agent_type = 'CRITIC';

UPDATE audit_task
SET status = 'FAILED',
    current_stage = '旧版 Critic 审核任务已终止，请重新发起增量审计',
    error_message = '当前版本已移除 Critic 模型审核阶段',
    completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP)
WHERE status = 'CRITIC_REVIEW';

ALTER TABLE agent_run ADD CONSTRAINT chk_agent_run_current_type
    CHECK (agent_type IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                          'SENSITIVE_INFORMATION', 'STORED_XSS', 'VALIDATION_BYPASS', 'REPORT'));

ALTER TABLE agent_event ADD CONSTRAINT chk_agent_event_current_type
    CHECK (agent_type IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                          'SENSITIVE_INFORMATION', 'STORED_XSS', 'VALIDATION_BYPASS', 'REPORT'));

ALTER TABLE audit_task ADD CONSTRAINT chk_audit_task_current_status
    CHECK (status IN ('UPLOADED', 'MATERIALIZING', 'DIFFING', 'INVENTORY', 'INDEXING',
                      'RECON', 'AGENT_RECON', 'PLANNING', 'ANALYSIS',
                      'RESULT_VALIDATION', 'REPORTING', 'COMPLETED', 'FAILED', 'CANCELLED'));
