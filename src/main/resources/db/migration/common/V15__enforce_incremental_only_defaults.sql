UPDATE audit_task
SET scan_mode = 'INCREMENTAL'
WHERE scan_mode <> 'INCREMENTAL';

UPDATE code_chunk
SET analysis_scope = 'CONTEXT'
WHERE analysis_scope = 'FULL';

UPDATE finding
SET delta_status = 'NEW'
WHERE delta_status IN ('BASELINE', 'REGRESSED', 'AFFECTED');

ALTER TABLE audit_task ALTER COLUMN scan_mode SET DEFAULT 'INCREMENTAL';
ALTER TABLE code_chunk ALTER COLUMN analysis_scope SET DEFAULT 'CONTEXT';
