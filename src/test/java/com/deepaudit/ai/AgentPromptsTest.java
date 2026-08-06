package com.deepaudit.ai;

import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AgentPromptsTest {

    @Test
    void triageDefinesIncrementalTermsWithoutImplementationHistory() {
        String prompt = AgentPrompts.incrementalTriage();

        assertThat(prompt)
                .contains("Base 是比较基准提交", "Target 是正在审计的目标提交",
                        "CHANGED 是在 Base 与 Target", "Guard 是", "mandatoryTypes", "focusRanges")
                .doesNotContain("Triage 不接收 IMPACTED", "不负责建立完整调用链", "去除代码量");
        assertThat(prompt.indexOf("CHANGED 是")).isLessThan(prompt.indexOf("决策规则"));
    }

    @Test
    void professionalPromptDefinesPrefetchedCandidatesAndEvidenceBoundary() {
        String prompt = AgentPrompts.professionalAgent(VulnerabilityType.AUTHORIZATION);

        assertThat(prompt)
                .contains("turn.target 是当前 CHANGED", "IMPACTED 是未改变",
                        "预取候选只有 candidateId", "read_verified_relations",
                        "VERIFIED_EVIDENCE", "UNVERIFIED_CANDIDATE")
                .contains("任务", "输入术语", "调查规则", "证据规则", "响应协议")
                .contains("不再有第二个模型替你补查证据或重新判断");
    }

    @Test
    void promptSectionsAreSeparatedAndSensitiveAgentKeepsItsBoundary() {
        String prompt = AgentPrompts.professionalAgent(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE);

        assertThat(prompt)
                .contains("\n\n输入术语", "\n\n工具", "\n\n安全边界")
                .contains("只调查敏感信息泄露", "不承担越权漏洞判断");
    }

    @Test
    void storedXssAgentRequiresTheCompletePersistencePath() {
        String prompt = AgentPrompts.professionalAgent(VulnerabilityType.STORED_XSS);

        assertThat(prompt)
                .contains("外部输入", "持久化写入", "同一数据的读取", "HTML 输出")
                .contains("共享 Repository", "@RequestBody", "@RequestParam");
    }
}
