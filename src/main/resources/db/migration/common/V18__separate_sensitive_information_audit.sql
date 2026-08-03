ALTER TABLE finding DROP CONSTRAINT chk_finding_current_type;
ALTER TABLE audit_hypothesis DROP CONSTRAINT chk_hypothesis_current_type;
ALTER TABLE security_flow DROP CONSTRAINT chk_security_flow_current_type;
ALTER TABLE agent_run DROP CONSTRAINT chk_agent_run_current_type;
ALTER TABLE agent_event DROP CONSTRAINT chk_agent_event_current_type;

DELETE FROM finding WHERE type = 'UNAUTHORIZED_DISCLOSURE';
DELETE FROM audit_hypothesis WHERE type = 'UNAUTHORIZED_DISCLOSURE';
DELETE FROM security_flow WHERE type = 'UNAUTHORIZED_DISCLOSURE';

ALTER TABLE finding ADD CONSTRAINT chk_finding_current_type
    CHECK (type IN ('AUTHORIZATION', 'SQL_INJECTION', 'SENSITIVE_INFORMATION_DISCLOSURE',
                    'STORED_XSS', 'VALIDATION_BYPASS'));

ALTER TABLE audit_hypothesis ADD CONSTRAINT chk_hypothesis_current_type
    CHECK (type IN ('AUTHORIZATION', 'SQL_INJECTION', 'SENSITIVE_INFORMATION_DISCLOSURE',
                    'STORED_XSS', 'VALIDATION_BYPASS'));

ALTER TABLE security_flow ADD CONSTRAINT chk_security_flow_current_type
    CHECK (type IN ('AUTHORIZATION', 'SQL_INJECTION', 'SENSITIVE_INFORMATION_DISCLOSURE',
                    'STORED_XSS', 'VALIDATION_BYPASS'));

ALTER TABLE agent_run ADD CONSTRAINT chk_agent_run_current_type
    CHECK (agent_type IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                          'SENSITIVE_INFORMATION', 'STORED_XSS', 'VALIDATION_BYPASS', 'CRITIC', 'REPORT'));

ALTER TABLE agent_event ADD CONSTRAINT chk_agent_event_current_type
    CHECK (agent_type IN ('RECON', 'ORCHESTRATOR', 'SQL_INJECTION', 'AUTHORIZATION',
                          'SENSITIVE_INFORMATION', 'STORED_XSS', 'VALIDATION_BYPASS', 'CRITIC', 'REPORT'));
