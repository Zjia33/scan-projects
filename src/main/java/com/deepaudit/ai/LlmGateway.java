package com.deepaudit.ai;

import com.deepaudit.agent.IncrementalReviewUnit;
import com.deepaudit.agent.TriageDisposition;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.recon.TechnologyProfile;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public interface LlmGateway {

    ReconInsight inspectProject(UUID taskId, ReconSummary summary);

    // 只基于真实 Base/Target 变更对全部 CHANGED 审查位置做调查/跳过路由。
    TriagePlan triageIncremental(UUID taskId, ReconInsight recon,
                                 List<IncrementalReviewUnit> reviewUnits);

    AgentDecision decide(AgentTurn turn);

    ReportNarrative writeReport(ReportRequest request);

    record Target(long chunkId, String filePath, String symbolName, String endpoint,
                  String chunkType, String parameters, String annotations,
                  String calledSymbols, String codeExcerpt, String changeType,
                  String analysisScope, String baseCodeExcerpt, List<VulnerabilityType> hints,
                  int startLine, int endLine) {
        public Target(long chunkId, String filePath, String symbolName, String endpoint,
                      String chunkType, String parameters, String annotations,
                      String calledSymbols, String codeExcerpt, String changeType,
                      String analysisScope, String baseCodeExcerpt, List<VulnerabilityType> hints) {
            this(chunkId, filePath, symbolName, endpoint, chunkType, parameters, annotations,
                    calledSymbols, codeExcerpt, changeType, analysisScope, baseCodeExcerpt, hints, 0, 0);
        }
    }

    record ReconInsight(String architectureSummary, TechnologyProfile technologyProfile) {
        // 校验并规范化 ReconInsight 的构造参数。
        public ReconInsight {
            architectureSummary = architectureSummary == null ? "" : architectureSummary;
            technologyProfile = technologyProfile == null ? TechnologyProfile.empty() : technologyProfile;
        }
    }

    record TriageDecision(String unitId, long primaryChunkId, TriageDisposition disposition,
                          List<VulnerabilityType> vulnerabilityTypes, String reason,
                          List<LineRange> focusRanges, List<String> investigationQuestions) {
        // 校验并规范化 TriageDecision 的构造参数。
        public TriageDecision {
            vulnerabilityTypes = vulnerabilityTypes == null ? List.of() : vulnerabilityTypes.stream()
                    .filter(java.util.Objects::nonNull).distinct().toList();
            focusRanges = focusRanges == null ? List.of() : focusRanges.stream()
                    .filter(java.util.Objects::nonNull).distinct().toList();
            investigationQuestions = investigationQuestions == null ? List.of()
                    : investigationQuestions.stream().filter(java.util.Objects::nonNull)
                    .map(String::strip).filter(value -> !value.isBlank()).distinct().toList();
        }

    }

    record LineRange(int startLine, int endLine) {
    }

    record TriagePlan(String summary, List<TriageDecision> decisions) {
        // 校验并规范化 TriagePlan 的构造参数。
        public TriagePlan {
            decisions = decisions == null ? List.of() : List.copyOf(decisions);
        }
    }

    record Observation(String tool, Map<String, Object> arguments, String result) {
        // 校验并规范化 Observation 的构造参数。
        public Observation {
            arguments = safeArguments(arguments);
        }
    }

    record AgentBudget(int currentRound, int totalDecisionRounds,
                       int decisionRoundsRemainingAfterThis,
                       int toolCallsUsed, int toolCallsLimit, int toolCallsRemaining,
                       boolean finalDecisionOnly) {
    }

    record AgentTurn(UUID taskId, AgentType agentType, VulnerabilityType vulnerabilityType,
                     Target target, String ruleHint, String semanticEvidence, ReconInsight recon,
                     List<Observation> observations, int iteration, AgentBudget budget) {
    }

    record FindingProposal(VulnerabilityType type, Severity severity, Confidence confidence,
                           String title, String description, String remediation,
                           Long primaryChunkId, List<Long> evidenceChunkIds,
                           Integer vulnerabilityStartLine, Integer vulnerabilityEndLine) {
        // 校验并规范化 FindingProposal 的构造参数。
        public FindingProposal {
            evidenceChunkIds = evidenceChunkIds == null ? List.of() : List.copyOf(evidenceChunkIds);
        }

        public FindingProposal(VulnerabilityType type, Severity severity, Confidence confidence,
                               String title, String description, String remediation,
                               Long primaryChunkId, List<Long> evidenceChunkIds) {
            this(type, severity, confidence, title, description, remediation,
                    primaryChunkId, evidenceChunkIds, null, null);
        }
    }

    record AgentDecision(String action, String tool, Map<String, Object> arguments,
                         String summary, FindingProposal finding) {
        // 校验并规范化 AgentDecision 的构造参数。
        public AgentDecision {
            arguments = safeArguments(arguments);
        }
    }

    record ReportFinding(VulnerabilityType type, Severity severity, Confidence confidence,
                         String title, String location, String description) {
    }

    record ReportRequest(UUID taskId, String projectName, ReconInsight recon,
                         List<ReportFinding> findings, int completedAgents, int rejectedHypotheses,
                         String auditContext) {
    }

    record ReportNarrative(String executiveSummary, String coverageSummary) {
    }

    private static Map<String, Object> safeArguments(Map<String, Object> arguments) {
        if (arguments == null || arguments.isEmpty()) return Map.of();
        Map<String, Object> safe = new LinkedHashMap<>();
        arguments.forEach((key, value) -> {
            if (key != null && value != null) safe.put(key, value);
        });
        return Map.copyOf(safe);
    }
}
