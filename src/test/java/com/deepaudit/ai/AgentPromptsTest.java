package com.deepaudit.ai;

import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AgentPromptsTest {

    @Test
    void reconPromptKeepsScopeAndSourceBoundaries() {
        String prompt = AgentPrompts.reconAgent();

        assertThat(prompt)
                .contains("只提炼项目架构，不执行漏洞审计")
                .contains("Target 构建描述、application/bootstrap 配置")
                .contains("语言与构建体系、应用框架、模块分层")
                .contains("不推测组件、不输出具体配置值")
                .contains("只返回 architectureSummary")
                .hasSizeLessThan(1_500);
    }

    @Test
    void initialTriagePromptKeepsEveryDecisionRule() {
        String prompt = AgentPrompts.incrementalTriage();

        assertThat(prompt)
                .contains("reviewUnits 是全部 CHANGED 位置")
                .contains("原样返回 unitId、primaryChunkId", "恰好给出一个决定")
                .contains("- 是 Base 删除/替换行", "+ 是 Target 新增/替换行")
                .contains("INVESTIGATE", "NEED_CONTEXT", "SKIP")
                .contains("vulnerabilityTypes 至少包含一个来自 allowedTypes 的类型")
                .contains("vulnerabilityTypes 返回空数组")
                .contains("SQL_INJECTION", "AUTHORIZATION", "SENSITIVE_INFORMATION_DISCLOSURE")
                .contains("STORED_XSS", "VALIDATION_BYPASS")
                .contains("只有独立的具体假设才返回多个类型")
                .hasSizeLessThan(2_500);
    }

    @Test
    void finalTriagePromptEnforcesSingleBinaryDecision() {
        String prompt = AgentPrompts.incrementalTriageFinal();

        assertThat(prompt)
                .contains("唯一一次补充上下文复判")
                .contains("原样返回 unitId、primaryChunkId", "只返回一个决定")
                .contains("只能是 INVESTIGATE 或 SKIP")
                .contains("不得再次返回 NEED_CONTEXT")
                .contains("allowedTypes", "vulnerabilityTypes=[]")
                .hasSizeLessThan(2_200);
    }

    @Test
    void professionalPromptIsCompactAndKeepsTheInvestigationContract() {
        String prompt = AgentPrompts.professionalAgent(VulnerabilityType.SQL_INJECTION);

        assertThat(prompt)
                .contains("当前只调查 SQL_INJECTION")
                .contains("action 只能是 TOOL、FINDING、REJECT")
                .contains("输入、失效控制、危险操作和影响")
                .contains("primaryChunkId 必须包含在 evidenceChunkIds 中")
                .contains("target、semanticEvidence.evidenceChunkIds 或工具返回的 evidenceChunkIds")
                .contains("真实 Target 行", "只覆盖关键语句")
                .contains("保留当前 CHANGED target", "IMPACTED", "不能替代 CHANGED")
                .contains("UNVERIFIED_CANDIDATE/candidateChunkIds 只能作为线索")
                .contains("候选流程：搜索 -> read_source", "verify_relation")
                .contains("\"action\":\"TOOL\"", "\"action\":\"REJECT\"", "\"action\":\"FINDING\"")
                .contains("severity 为 CRITICAL|HIGH|MEDIUM|LOW")
                .contains("confidence 为 HIGH|MEDIUM|LOW")
                .contains("summary、title、description、remediation 面向报告读者")
                .contains("禁止出现 Chunk/代码块编号、CHUNK_ID、primaryChunkId")
                .contains("内部 ID 只能出现在 arguments 或 finding 的结构化 ID/行号字段中")
                .contains("必填字段不得省略", "条件字段按对应规则填写")
                .hasSizeLessThan(13_000);
    }

    @Test
    void sensitiveInformationPromptKeepsSecretHandlingBoundaries() {
        String prompt = AgentPrompts.professionalAgent(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE);

        assertThat(prompt)
                .contains("只调查敏感信息泄露，不承担越权漏洞判断")
                .contains("密码、Token、API Key、Client Secret、私钥及连接凭据")
                .contains("环境变量占位符、空值、公开密钥、配置开关和过期时间本身不是秘密")
                .contains("不得在 summary、title、description 或 remediation 中复述完整密码值");
    }

    @Test
    void criticPromptKeepsVerdictLocationAndIncrementalRules() {
        String prompt = AgentPrompts.criticAgent();

        assertThat(prompt)
                .contains("独立 Critic Agent", "不因 FINDING 或高 confidence 直接确认")
                .contains("CONFIRMED", "REJECTED", "INSUFFICIENT_EVIDENCE")
                .contains("counterEvidenceChunkIds 只引用输入中的真实反证 CHUNK_ID")
                .contains("非 REJECTED 时 counterEvidenceChunkIds=[]")
                .contains("从 locationCandidates 选择 locationCandidateId")
                .contains("原样复制其 chunkId/startLine/endLine")
                .contains("deltaStatus、rootCauseKind、locationRole")
                .contains("confirmed=false 时不要求 deltaStatus", "不得为这些条件字段编造占位值")
                .contains("NEW", "PERSISTING", "与 Target 直接变更或影响链的因果关系")
                .hasSizeLessThan(2_500);
    }

    @Test
    void locationRepairPromptOnlyAllowsCandidateSelection() {
        String prompt = AgentPrompts.locationRepair();

        assertThat(prompt)
                .contains("漏洞已由 Critic 确认", "不得重新判断、否决或改变类型")
                .contains("只能从 locationCandidates 中选择")
                .contains("原样返回 locationCandidateId")
                .contains("不得计算行号或创造位置")
                .contains("reason 使用简短中文")
                .hasSizeLessThan(1_400);
    }

    @Test
    void reportPromptOnlyRewritesConfirmedFacts() {
        String prompt = AgentPrompts.reportAgent();

        assertThat(prompt)
                .contains("只将已通过 Critic 的事实改写")
                .contains("executiveSummary")
                .contains("当前证据范围内未形成确认漏洞", "不得声称绝对安全")
                .contains("不得新增漏洞、改变类型/等级或扩大影响")
                .contains("executiveSummary 面向报告读者")
                .contains("禁止出现 Chunk/代码块编号、CHUNK_ID、primaryChunkId")
                .doesNotContain("coverageSummary", "审计覆盖")
                .hasSizeLessThan(1_400);
    }

    @Test
    void jsonRepairPromptPreservesSchemaAndPrimitiveTypes() {
        String prompt = AgentPrompts.jsonRepair("第 1 行缺少 confirmed");

        assertThat(prompt)
                .contains("第 1 行缺少 confirmed")
                .contains("不得增减 schema 字段或省略必填字段")
                .contains("枚举、ID、数字和 boolean 保持规定类型")
                .contains("summary/title 不超过60个汉字")
                .contains("description/remediation 不超过180个汉字")
                .contains("只输出 JSON，不输出 Markdown 或解释")
                .hasSizeLessThan(800);
    }
}
