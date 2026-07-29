package com.deepaudit;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.agent.TriageDisposition;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.ibatis.session.SqlSessionFactory;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test")
@SpringBootTest
@Import(TestLlmConfiguration.class)
class DeepAuditApplicationTests {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private SqlSessionFactory sqlSessionFactory;

    @Autowired
    private Flyway flyway;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void loadsMyBatisAndFlywayWithoutJpa() {
        assertThat(sqlSessionFactory).isNotNull();
        assertThat(applicationContext.containsBean("entityManagerFactory")).isFalse();
        assertThat(applicationContext.containsBean("projectMapper")).isTrue();
        assertThat(flyway.info().applied()).hasSizeGreaterThanOrEqualTo(3);
    }

    @Test
    void removesLegacyRetrievalStorageFromCurrentSchema() {
        Integer cacheTables = jdbcTemplate.queryForObject("""
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.TABLES
                WHERE UPPER(TABLE_NAME) = 'EMBEDDING_CACHE'
                """, Integer.class);
        Integer vectorColumns = jdbcTemplate.queryForObject("""
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE UPPER(TABLE_NAME) = 'CODE_CHUNK'
                  AND UPPER(COLUMN_NAME) IN ('EMBEDDING', 'EMBEDDING_VECTOR')
                """, Integer.class);

        assertThat(cacheTables).isZero();
        assertThat(vectorColumns).isZero();
    }

    @Test
    void acceptsCaseInsensitiveEnumValuesReturnedByModels() throws Exception {
        String modelJson = """
                {
                  "action": "finding",
                  "summary": "发现字符串拼接 SQL",
                  "finding": {
                    "type": "sql_injection",
                    "severity": "critical",
                    "confidence": "High",
                    "title": "SQL 注入",
                    "description": "用户输入未经参数化处理",
                    "remediation": "使用占位符",
                    "primaryChunkId": 1001,
                    "evidenceChunkIds": [1001]
                  }
                }
                """;

        LlmGateway.AgentDecision decision = objectMapper.readValue(modelJson, LlmGateway.AgentDecision.class);

        assertThat(decision.finding().type()).isEqualTo(VulnerabilityType.SQL_INJECTION);
        assertThat(decision.finding().severity()).isEqualTo(Severity.CRITICAL);
        assertThat(decision.finding().confidence()).isEqualTo(Confidence.HIGH);
    }

    @Test
    void normalizesTriageEnumsAndKeepsUnknownValuesSkippable() throws Exception {
        String modelJson = """
                {
                  "summary": "权限审计分流",
                  "decisions": [
                    {
                      "unitId": "chunk-10",
                      "primaryChunkId": 10,
                      "disposition": "investigate",
                      "vulnerabilityTypes": ["UnauthorizedAccess"],
                      "reasonCodes": ["EXTERNAL_ENTRY"],
                      "requiredContext": [],
                      "reason": "未授权接口可能泄露敏感信息"
                    },
                    {
                      "unitId": "chunk-11",
                      "primaryChunkId": 11,
                      "disposition": "InventedDisposition",
                      "vulnerabilityTypes": ["InventedRisk"],
                      "reasonCodes": [],
                      "requiredContext": [],
                      "reason": "模型创造的未知类别"
                    }
                  ]
                }
                """;

        LlmGateway.TriagePlan plan = objectMapper.readValue(modelJson, LlmGateway.TriagePlan.class);

        assertThat(plan.decisions().get(0).disposition()).isEqualTo(TriageDisposition.INVESTIGATE);
        assertThat(plan.decisions().get(0).vulnerabilityTypes())
                .containsExactly(VulnerabilityType.UNAUTHORIZED_DISCLOSURE);
        assertThat(plan.decisions().get(1).disposition()).isNull();
        assertThat(plan.decisions().get(1).vulnerabilityTypes()).isEmpty();
    }

    @Test
    void mergesHorizontalAndVerticalAuthorizationAliasesIntoOneType() {
        assertThat(VulnerabilityType.fromModelValue("AUTHORIZATION"))
                .isEqualTo(VulnerabilityType.AUTHORIZATION);
        assertThat(VulnerabilityType.fromModelValue("HORIZONTAL_AUTHORIZATION"))
                .isEqualTo(VulnerabilityType.AUTHORIZATION);
        assertThat(VulnerabilityType.fromModelValue("vertical_authorization"))
                .isEqualTo(VulnerabilityType.AUTHORIZATION);
        assertThat(VulnerabilityType.fromModelValue("水平越权"))
                .isEqualTo(VulnerabilityType.AUTHORIZATION);
        assertThat(VulnerabilityType.fromModelValue("垂直越权"))
                .isEqualTo(VulnerabilityType.AUTHORIZATION);
    }
}
