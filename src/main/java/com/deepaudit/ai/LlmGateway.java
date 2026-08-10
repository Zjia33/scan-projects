package com.deepaudit.ai;

import com.deepaudit.agent.IncrementalReviewUnit;
import com.deepaudit.agent.TriageDisposition;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.recon.TechnologyProfile;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public interface LlmGateway {

    ReconInsight inspectProject(UUID taskId, ReconSummary summary);

    // 首次只基于真实统一变更上下文和轻量关系事实分流全部 CHANGED 审查位置。
    TriagePlan triageIncremental(UUID taskId, ReconInsight recon,
                                 List<IncrementalReviewUnit> reviewUnits);

    // 对补充上下文后的单个增量位置执行唯一一次明确复判；必须返回 INVESTIGATE 或 SKIP。
    default TriagePlan triageIncrementalFinal(UUID taskId, ReconInsight recon,
                                              IncrementalReviewUnit reviewUnit) {
        return triageIncremental(taskId, recon, List.of(reviewUnit));
    }

    AgentDecision decide(AgentTurn turn);

    CriticDecision critique(CriticRequest request);

    // Critic 已确认漏洞但首次定位不合法时，只修复位置选择，不重新判断漏洞是否成立。
    LocationDecision repairLocation(LocationRepairRequest request);

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
                          List<VulnerabilityType> vulnerabilityTypes, String reason) {
        // 校验并规范化 TriageDecision 的构造参数。
        public TriageDecision {
            vulnerabilityTypes = vulnerabilityTypes == null ? List.of() : vulnerabilityTypes.stream()
                    .filter(java.util.Objects::nonNull).distinct().toList();
        }
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

    record AgentTurn(UUID taskId, AgentType agentType, VulnerabilityType vulnerabilityType,
                     Target target, String ruleHint, String semanticEvidence, ReconInsight recon,
                     List<Observation> observations, int iteration) {
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

    record CriticRequest(UUID taskId, AgentType sourceAgent, FindingProposal proposal,
                         String evidence, String independentSemanticEvidence, ReconInsight recon,
                         String changeType, String analysisScope, String changeContext,
                         List<LocationCandidate> locationCandidates) {
        public CriticRequest {
            locationCandidates = locationCandidates == null ? List.of() : List.copyOf(locationCandidates);
        }
    }

    record CriticDecision(Boolean confirmed, Confidence confidence, String reason,
                          FindingDeltaStatus deltaStatus, Long primaryChunkId,
                          Integer vulnerabilityStartLine, Integer vulnerabilityEndLine,
                          String rootCauseKind, String locationRole, String locationCandidateId,
                          CriticVerdict verdict, List<Long> counterEvidenceChunkIds) {
        public CriticDecision {
            counterEvidenceChunkIds = counterEvidenceChunkIds == null
                    ? List.of() : List.copyOf(counterEvidenceChunkIds);
        }

        public CriticDecision(Boolean confirmed, Confidence confidence, String reason,
                              FindingDeltaStatus deltaStatus, Long primaryChunkId,
                              Integer vulnerabilityStartLine, Integer vulnerabilityEndLine,
                              String rootCauseKind, String locationRole, String locationCandidateId) {
            this(confirmed, confidence, reason, deltaStatus, primaryChunkId,
                    vulnerabilityStartLine, vulnerabilityEndLine, rootCauseKind, locationRole,
                    locationCandidateId, Boolean.TRUE.equals(confirmed)
                    ? CriticVerdict.CONFIRMED : CriticVerdict.REJECTED, List.of());
        }

        public CriticDecision(Boolean confirmed, Confidence confidence, String reason,
                              FindingDeltaStatus deltaStatus, Long primaryChunkId,
                              Integer vulnerabilityStartLine, Integer vulnerabilityEndLine,
                              String rootCauseKind, String locationRole, String locationCandidateId,
                              CriticVerdict verdict) {
            this(confirmed, confidence, reason, deltaStatus, primaryChunkId,
                    vulnerabilityStartLine, vulnerabilityEndLine, rootCauseKind, locationRole,
                    locationCandidateId, verdict, List.of());
        }
    }

    enum CriticVerdict {
        CONFIRMED, REJECTED, INSUFFICIENT_EVIDENCE
    }

    // 由后端从真实证据源码生成的可选位置；模型只能选择 candidateId，不能创造行号。
    record LocationCandidate(String candidateId, long chunkId, String filePath, String symbolName,
                             int startLine, int endLine, String source, List<String> roles,
                             String analysisScope) {
        public LocationCandidate {
            roles = roles == null ? List.of() : List.copyOf(roles);
        }
    }

    // 位置修复只接收已经确认的漏洞事实和合法候选，不允许重新否决漏洞。
    record LocationRepairRequest(UUID taskId, VulnerabilityType vulnerabilityType, String title,
                                 String description, String criticReason, String rootCauseKind,
                                 String previousLocation, String failureReason,
                                 List<LocationCandidate> locationCandidates) {
        public LocationRepairRequest {
            locationCandidates = locationCandidates == null ? List.of() : List.copyOf(locationCandidates);
        }
    }

    // 专用定位调用只返回后端生成的候选 ID。
    record LocationDecision(String locationCandidateId, String reason) {
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
