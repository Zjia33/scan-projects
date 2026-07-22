package com.deepaudit.ai;

import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.VulnerabilityType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteLlmGatewayTest {

    @Test
    void locallyRepairsUnescapedQuotesWithoutAnotherModelCall() {
        AiProperties properties = properties(2);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties,
                """
                        {"action":"FINDING","tool":null,"query":null,"limit":1,"summary":"发现问题",
                         "finding":{"type":"SQL_INJECTION","severity":"HIGH","confidence":"HIGH",
                         "title":"SQL 注入","description":"攻击者可访问 "http://internal" 获取数据",
                         "remediation":"使用参数化查询","primaryChunkId":1001,"evidenceChunkIds":[1001]}}
                        """);

        LlmGateway.AgentDecision decision = gateway.decide(turn());

        assertThat(decision.action()).isEqualTo("FINDING");
        assertThat(decision.finding().type()).isEqualTo(VulnerabilityType.SQL_INJECTION);
        assertThat(gateway.requests).hasSize(1);
        assertThat(gateway.requests.get(0).get(0).get("content"))
                .contains("所有供人阅读的摘要", "简体中文", "technologyProfile",
                        "RAG_CANDIDATE", "verify_relation", "VERIFIED_EVIDENCE");
    }

    @Test
    void asksModelToRebuildJsonWhenLocalRepairCannotRecoverIt() {
        AiProperties properties = properties(2);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, "{invalid", """
                {"action":"REJECT","tool":null,"query":null,"limit":1,
                 "summary":"没有足够证据支持漏洞结论","finding":null}
                """);

        LlmGateway.AgentDecision decision = gateway.decide(turn());

        assertThat(decision.action()).isEqualTo("REJECT");
        assertThat(gateway.requests).hasSize(2);
        assertThat(gateway.requests.get(1).get(gateway.requests.get(1).size() - 1).get("content"))
                .contains("从头重建", "禁止源码", "不超过 180 个汉字");
    }

    @Test
    void stopsAfterConfiguredRepairBudgetIsExhausted() {
        AiProperties properties = properties(1);
        StubRemoteLlmGateway gateway = new StubRemoteLlmGateway(properties, "{invalid", "{still invalid");

        assertThatThrownBy(() -> gateway.decide(turn()))
                .isInstanceOf(AiResponseFormatException.class)
                .hasMessageContaining("2 次响应后仍未返回合法 JSON");
        assertThat(gateway.requests).hasSize(2);
    }

    private AiProperties properties(int repairAttempts) {
        AiProperties properties = new AiProperties();
        properties.setRequired(true);
        properties.setJsonRepairAttempts(repairAttempts);
        return properties;
    }

    private LlmGateway.AgentTurn turn() {
        LlmGateway.Target target = new LlmGateway.Target(1001L, "UserController.java", "search", "/search",
                "JAVA_METHOD", "String name", "@GetMapping", "queryForList", "return query(name);", List.of());
        LlmGateway.ReconInsight recon = new LlmGateway.ReconInsight("Spring MVC", List.of("/search"),
                List.of(), List.of("动态 SQL"));
        return new LlmGateway.AgentTurn(UUID.randomUUID(), AgentType.SQL_INJECTION,
                VulnerabilityType.SQL_INJECTION, target, null, "没有预计算语义路径", recon, List.of(), 1);
    }

    private static class StubRemoteLlmGateway extends RemoteLlmGateway {
        private final Deque<String> responses = new ArrayDeque<>();
        private final List<List<Map<String, String>>> requests = new ArrayList<>();

        StubRemoteLlmGateway(AiProperties properties, String... responses) {
            super(properties, new ObjectMapper());
            this.responses.addAll(List.of(responses));
        }

        @Override
        protected String requestCompletion(List<Map<String, String>> messages) {
            requests.add(messages.stream().map(Map::copyOf).toList());
            return responses.removeFirst();
        }
    }
}
