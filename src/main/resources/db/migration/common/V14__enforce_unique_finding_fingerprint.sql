UPDATE finding
SET fingerprint = LOWER(
        REPLACE(CAST(id AS VARCHAR(36)), '-', '')
        || REPLACE(CAST(id AS VARCHAR(36)), '-', '')
    )
WHERE fingerprint = '';

DELETE FROM finding
WHERE id IN (
    SELECT id
    FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY task_id, fingerprint
                   ORDER BY created_at, id
               ) AS duplicate_number
        FROM finding
    ) ranked_findings
    WHERE duplicate_number > 1
);

DROP INDEX idx_finding_fingerprint;
CREATE UNIQUE INDEX uq_finding_task_fingerprint ON finding(task_id, fingerprint);
