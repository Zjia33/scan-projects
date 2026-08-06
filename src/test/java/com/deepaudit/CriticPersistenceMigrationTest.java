package com.deepaudit;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CriticPersistenceMigrationTest {

    @Test
    void removesHistoricalCriticRowsAndTerminatesLegacyReviewTask() {
        String url = "jdbc:h2:mem:critic-migration-" + UUID.randomUUID()
                + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
        DriverManagerDataSource dataSource = new DriverManagerDataSource(url, "sa", "");
        Flyway.configure().dataSource(dataSource)
                .locations("classpath:db/migration/common")
                .target(MigrationVersion.fromVersion("21")).load().migrate();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        UUID projectId = UUID.randomUUID();
        UUID taskId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO audit_project (id, name, storage_path, created_at)
                VALUES (?, ?, ?, ?)
                """, projectId, "旧任务", "data/legacy", Instant.now());
        jdbc.update("""
                INSERT INTO audit_task (id, project_id, status, progress, current_stage, created_at)
                VALUES (?, ?, 'CRITIC_REVIEW', 80, 'Critic 审核中', ?)
                """, taskId, projectId, Instant.now());
        jdbc.update("""
                INSERT INTO agent_run
                    (id, task_id, agent_type, status, step_count, tool_call_count,
                     model_call_count, started_at)
                VALUES (?, ?, 'CRITIC', 'RUNNING', 1, 0, 1, ?)
                """, runId, taskId, Instant.now());
        jdbc.update("""
                INSERT INTO agent_event (task_id, run_id, agent_type, event_type, message, created_at)
                VALUES (?, ?, 'CRITIC', 'MODEL_CALL', '旧审核事件', ?)
                """, taskId, runId, Instant.now());

        Flyway.configure().dataSource(dataSource)
                .locations("classpath:db/migration/common").load().migrate();

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM agent_run WHERE agent_type='CRITIC'",
                Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM agent_event WHERE agent_type='CRITIC'",
                Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT status FROM audit_task WHERE id=?",
                String.class, taskId)).isEqualTo("FAILED");
        assertThat(jdbc.queryForObject("SELECT error_message FROM audit_task WHERE id=?",
                String.class, taskId)).contains("已移除 Critic");
    }
}
