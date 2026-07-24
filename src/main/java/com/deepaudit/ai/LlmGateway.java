package com.deepaudit.ai;

import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.recon.ReconSummary;
import com.deepaudit.recon.TechnologyProfile;

import java.util.List;
import java.util.UUID;

public interface LlmGateway {

    ReconInsight inspectProject(UUID taskId, ReconSummary summary, List<Target> representativeTargets);

    AuditPlan createPlan(UUID taskId, ReconInsight recon, List<Target> targets);

    AgentDecision decide(AgentTurn turn);

    CriticDecision critique(CriticRequest request);

    ReportNarrative writeReport(ReportRequest request);

    record Target(long chunkId, String filePath, String symbolName, String endpoint,
                  String chunkType, String parameters, String annotations,
                  String calledSymbols, String codeExcerpt, String changeType,
                  String analysisScope, String baseCodeExcerpt, List<VulnerabilityType> hints) {
    }

    record ReconInsight(String architectureSummary, List<String> attackSurfaces,
                        List<String> securityMechanisms, List<String> riskAreas,
                        TechnologyProfile technologyProfile) {
        public ReconInsight {
            attackSurfaces = attackSurfaces == null ? List.of() : List.copyOf(attackSurfaces);
            securityMechanisms = securityMechanisms == null ? List.of() : List.copyOf(securityMechanisms);
            riskAreas = riskAreas == null ? List.of() : List.copyOf(riskAreas);
            technologyProfile = technologyProfile == null ? TechnologyProfile.empty() : technologyProfile;
        }

        public ReconInsight(String architectureSummary, List<String> attackSurfaces,
                            List<String> securityMechanisms, List<String> riskAreas) {
            this(architectureSummary, attackSurfaces, securityMechanisms, riskAreas, TechnologyProfile.empty());
        }
    }

    record PlannedTask(long chunkId, AgentType agentType, VulnerabilityType vulnerabilityType, String reason) {
    }

    record AuditPlan(String summary, List<PlannedTask> tasks) {
        public AuditPlan {
            tasks = tasks == null ? List.of() : List.copyOf(tasks);
        }
    }

    record Observation(String tool, String query, String result) {
    }

    record AgentTurn(UUID taskId, AgentType agentType, VulnerabilityType vulnerabilityType,
                     Target target, String ruleHint, String semanticEvidence, ReconInsight recon,
                     List<Observation> observations, int iteration) {
    }

    record FindingProposal(VulnerabilityType type, Severity severity, Confidence confidence,
                           String title, String description, String remediation,
                           Long primaryChunkId, List<Long> evidenceChunkIds) {
        public FindingProposal {
            evidenceChunkIds = evidenceChunkIds == null ? List.of() : List.copyOf(evidenceChunkIds);
        }
    }

    record AgentDecision(String action, String tool, String query, int limit,
                         String summary, FindingProposal finding) {
    }

    record CriticRequest(UUID taskId, AgentType sourceAgent, FindingProposal proposal,
                         String evidence, String independentSemanticEvidence, ReconInsight recon,
                         String changeType, String analysisScope, String baseCodeExcerpt) {
    }

    record CriticDecision(boolean confirmed, Confidence confidence, String reason,
                          FindingDeltaStatus deltaStatus) {
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
}
