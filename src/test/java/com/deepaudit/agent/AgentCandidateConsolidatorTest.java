package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AgentCandidateConsolidatorTest {

    @Test
    void mergesOnlyOverlappingProposalsForTheSameTypeAndPrimaryChunk() {
        AgentCandidate first = candidate(101L, 61, 62, List.of(101L, 201L), "控制器调用链");
        AgentCandidate duplicate = candidate(101L, 62, 63, List.of(101L, 301L), "变更方法证据");
        AgentCandidate separateSink = candidate(101L, 70, 70, List.of(101L), "同一方法中的另一处输出");

        List<AgentCandidate> result = AgentCandidateConsolidator.consolidate(
                List.of(first, duplicate, separateSink));

        assertThat(result).hasSize(2);
        assertThat(result.get(0).proposal().vulnerabilityStartLine()).isEqualTo(61);
        assertThat(result.get(0).proposal().vulnerabilityEndLine()).isEqualTo(63);
        assertThat(result.get(0).proposal().evidenceChunkIds())
                .containsExactly(101L, 201L, 301L);
        assertThat(result.get(0).evidence()).contains("控制器调用链", "变更方法证据");
        assertThat(result.get(1).proposal().vulnerabilityStartLine()).isEqualTo(70);
    }

    @Test
    void keepsDifferentVulnerabilityTypesSeparateAtTheSameLocation() {
        AgentCandidate xss = candidate(101L, 61, 62, List.of(101L), "XSS");
        LlmGateway.FindingProposal sqlProposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "SQL 注入", "动态 SQL", "参数化查询",
                101L, List.of(101L), 61, 62);
        AgentCandidate sql = new AgentCandidate(
                AgentType.SQL_INJECTION, sqlProposal, "SQL", null);

        assertThat(AgentCandidateConsolidator.consolidate(List.of(xss, sql))).hasSize(2);
    }

    private AgentCandidate candidate(Long chunkId, int startLine, int endLine,
                                     List<Long> evidenceIds, String evidence) {
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.STORED_XSS, Severity.HIGH, Confidence.HIGH,
                "存储型 XSS", "未转义内容进入 HTML", "进行上下文相关编码",
                chunkId, evidenceIds, startLine, endLine);
        return new AgentCandidate(AgentType.STORED_XSS, proposal, evidence, null);
    }
}
