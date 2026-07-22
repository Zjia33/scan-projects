package com.deepaudit;

import com.deepaudit.ai.LlmGateway;
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

    @Test
    void loadsMyBatisAndFlywayWithoutJpa() {
        assertThat(sqlSessionFactory).isNotNull();
        assertThat(applicationContext.containsBean("entityManagerFactory")).isFalse();
        assertThat(applicationContext.containsBean("projectMapper")).isTrue();
        assertThat(flyway.info().applied()).hasSizeGreaterThanOrEqualTo(3);
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
    void normalizesModelAliasesAndKeepsUnknownPlanValuesSkippable() throws Exception {
        String modelJson = """
                {
                  "summary": "权限审计计划",
                  "tasks": [
                    {
                      "chunkId": 10,
                      "agentType": "AuthorizationAgent",
                      "vulnerabilityType": "UnauthorizedAccess",
                      "reason": "未授权接口可能泄露敏感信息"
                    },
                    {
                      "chunkId": 11,
                      "agentType": "InventedAgent",
                      "vulnerabilityType": "InventedRisk",
                      "reason": "模型创造的未知类别"
                    }
                  ]
                }
                """;

        LlmGateway.AuditPlan plan = objectMapper.readValue(modelJson, LlmGateway.AuditPlan.class);

        assertThat(plan.tasks().get(0).agentType()).isEqualTo(com.deepaudit.domain.AgentType.AUTHORIZATION);
        assertThat(plan.tasks().get(0).vulnerabilityType())
                .isEqualTo(VulnerabilityType.UNAUTHORIZED_DISCLOSURE);
        assertThat(plan.tasks().get(1).agentType()).isNull();
        assertThat(plan.tasks().get(1).vulnerabilityType()).isNull();
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
