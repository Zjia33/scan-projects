package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CriticAgentServiceTest {

    @Test
    void relocatesConfirmedFindingFromControllerToActualServiceOperation() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk controller = controller(taskId);
        CodeChunk vulnerableService = vulnerableService(taskId);
        LlmGateway.FindingProposal proposedAtController = new LlmGateway.FindingProposal(
                VulnerabilityType.FINANCIAL_RISK, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "服务端直接信任 quotedUnitPrice", "服务端查询可信价格",
                controller.getId(), List.of(controller.getId(), vulnerableService.getId()), 82, 83);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.FINANCIAL_RISK, "报价可以被客户端控制", controller.getId(),
                controller.getId() + "," + vulnerableService.getId(), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.FINANCIAL_RISK, proposedAtController, "旧的候选证据文本", hypothesis);

        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(controller.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, controller.getId(), "purchase"));
        when(semanticEvidenceService.independentCriticEvidence(
                taskId, controller.getId(), VulnerabilityType.FINANCIAL_RISK)).thenReturn("调用链证据");
        when(semanticEvidenceService.callSiteLines(eq(taskId), eq(vulnerableService.getId()), anySet()))
                .thenReturn(Map.of(controller.getId(), 84));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "实际风险发生在服务层扣款逻辑", FindingDeltaStatus.BASELINE,
                vulnerableService.getId(), 86, 88));

        Optional<Finding> result = service.review(taskId, candidate, recon(),
                List.of(controller, vulnerableService), ScanMode.FULL);

        assertThat(result).isPresent();
        Finding finding = result.orElseThrow();
        assertThat(finding.getFilePath()).isEqualTo("LabScenarioService.java");
        assertThat(finding.getStartLine()).isEqualTo(86);
        assertThat(finding.getEndLine()).isEqualTo(88);
        assertThat(finding.getEndpoint()).isEqualTo("/payments/purchase");
        assertThat(finding.getEvidence())
                .contains("[漏洞位置] LabScenarioService.java:86-88")
                .contains("[调用入口] LabScenarioController.java:84")
                .doesNotContain("旧的候选证据文本");
        assertThat(hypothesis.getPrimaryChunkId()).isEqualTo(vulnerableService.getId());
    }

    private CodeChunk controller(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId, "LabScenarioController.java",
                "LabScenarioController#purchase", "/payments/purchase", 79, 85, """
                @PreAuthorize("hasAuthority('TRANSFER_CREATE')")
                @PostMapping("/payments/purchase")
                public TransactionResult purchase(PurchaseRequest request) {
                    CurrentUser loginUser = securityContext.currentUser();
                    accountService.assertAccountBelongsToUser(loginUser.userId(), request.accountNo());
                    return labScenarioService.purchase(request);
                }
                """, "JAVA_METHOD", "PurchaseRequest request", "@PostMapping", "purchase");
        chunk.setId(1497L);
        return chunk;
    }

    private CodeChunk vulnerableService(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId, "LabScenarioService.java",
                "LabScenarioService#purchase", null, 86, 88, """
                BigDecimal total = request.quotedUnitPrice().multiply(BigDecimal.valueOf(request.quantity()));
                accountRepository.debit(request.accountNo(), total);
                return completed(total);
                """, "JAVA_METHOD", "PurchaseRequest request", "", "debit,completed");
        chunk.setId(1549L);
        return chunk;
    }

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("Spring MVC 银行业务", List.of("HTTP API"),
                List.of("Spring Security"), List.of("支付业务逻辑"));
    }
}
