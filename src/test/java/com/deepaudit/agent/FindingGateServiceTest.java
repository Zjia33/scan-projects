package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.HypothesisStatus;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class FindingGateServiceTest {

    @Test
    void acceptsProfessionalFindingWithChangedAnchorAndVerifiedImpactLocation() {
        UUID taskId = UUID.randomUUID();
        CodeChunk changed = chunk(taskId, 1L, AnalysisScope.CHANGED,
                "demo/Controller.java", 10, "return service.search(name);");
        CodeChunk impacted = chunk(taskId, 2L, AnalysisScope.IMPACTED,
                "demo/Service.java", 30, "return statement.executeQuery(sql);");
        AuditHypothesis hypothesis = hypothesis(taskId, 2L);
        AgentCandidate candidate = new AgentCandidate(AgentType.SQL_INJECTION,
                proposal(2L, List.of(1L, 2L), 30), hypothesis);
        AuditHypothesisMapper mapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        when(semantic.callSiteLines(taskId, 2L, java.util.Set.of(1L, 2L),
                Map.of(1L, changed, 2L, impacted)))
                .thenReturn(Map.of(1L, 10));
        FindingGateService service = new FindingGateService(mapper, semantic,
                mock(CodeGraphIntegrationService.class), mock(AgentTraceService.class));

        var findings = service.evaluate(taskId, List.of(candidate), List.of(changed, impacted));

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.getFilePath()).isEqualTo("demo/Service.java");
            assertThat(finding.getStartLine()).isEqualTo(30);
            assertThat(finding.getEvidence()).contains("[漏洞位置]", "[调用链]");
        });
        assertThat(hypothesis.getStatus()).isEqualTo(HypothesisStatus.CONFIRMED);
        assertThat(hypothesis.getValidationReason()).contains("确定性证据");
        verify(mapper).update(hypothesis);
    }

    @Test
    void rejectsFindingWhoseEvidenceHasNoChangedCausalAnchor() {
        UUID taskId = UUID.randomUUID();
        CodeChunk impacted = chunk(taskId, 2L, AnalysisScope.IMPACTED,
                "demo/Service.java", 30, "return statement.executeQuery(sql);");
        AuditHypothesis hypothesis = hypothesis(taskId, 2L);
        AgentCandidate candidate = new AgentCandidate(AgentType.SQL_INJECTION,
                proposal(2L, List.of(2L), 30), hypothesis);
        AuditHypothesisMapper mapper = mock(AuditHypothesisMapper.class);
        FindingGateService service = new FindingGateService(mapper,
                mock(SemanticEvidenceService.class), mock(CodeGraphIntegrationService.class),
                mock(AgentTraceService.class));

        var findings = service.evaluate(taskId, List.of(candidate), List.of(impacted));

        assertThat(findings).isEmpty();
        assertThat(hypothesis.getStatus()).isEqualTo(HypothesisStatus.INSUFFICIENT_EVIDENCE);
        assertThat(hypothesis.getValidationReason()).contains("缺少 CHANGED 增量因果锚点");
        verify(mapper).update(hypothesis);
    }

    @Test
    void relocatesDelegatingControllerProposalToVerifiedConcreteServiceOperation() {
        UUID taskId = UUID.randomUUID();
        CodeChunk controller = new CodeChunk(taskId, "demo/LabScenarioController.java",
                "LabScenarioController#purchase", "/api/lab/payments/purchase", 80, 85, """
                @PostMapping("/payments/purchase")
                public TransactionResult purchase(PurchaseRequest request) {
                    CurrentUser loginUser = securityContext.currentUser();
                    accountService.assertAccountBelongsToUser(loginUser.userId(), request.accountNo());
                    return labScenarioService.purchase(request);
                }
                """, "JAVA_METHOD", "PurchaseRequest request", "@PostMapping", "purchase");
        controller.setId(1L);
        controller.setAnalysisScope(AnalysisScope.CHANGED);
        CodeChunk serviceChunk = new CodeChunk(taskId, "demo/LabScenarioService.java",
                "LabScenarioService#purchase", null, 78, 89, """
                public TransactionResult purchase(PurchaseRequest request) {
                    if (request == null
                            || request.quotedUnitPrice() == null
                            || request.quotedUnitPrice().signum() <= 0
                            || request.quantity() <= 0
                            || !PRODUCT_CATALOG.containsKey(request.productCode())) {
                        throw new IllegalArgumentException("Invalid purchase request");
                    }
                    BigDecimal total = request.quotedUnitPrice().multiply(BigDecimal.valueOf(request.quantity()));
                    accountRepository.debit(request.accountNo(), total);
                    return completed(total);
                }
                """, "JAVA_METHOD", "PurchaseRequest request", "", "debit,completed");
        serviceChunk.setId(2L);
        serviceChunk.setAnalysisScope(AnalysisScope.CHANGED);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "客户端报价未经目录价格校验", "Controller 调用 Service 后直接使用 quotedUnitPrice 计算扣款金额",
                "使用服务端目录价格", 1L, List.of(1L, 2L), 84, 84);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.VALIDATION_BYPASS, "客户端报价进入扣款", 1L, "1,2", Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(AgentType.VALIDATION_BYPASS,
                proposal, hypothesis);
        AuditHypothesisMapper mapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semantic = mock(SemanticEvidenceService.class);
        when(semantic.callSiteLines(taskId, 2L, java.util.Set.of(1L, 2L),
                Map.of(1L, controller, 2L, serviceChunk))).thenReturn(Map.of());
        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        when(codeGraph.verifyDirectRelation(taskId, controller, serviceChunk,
                List.of(controller, serviceChunk)))
                .thenReturn(new CodeGraphIntegrationService.RelationCheck(true, "direct callee"));
        FindingGateService gate = new FindingGateService(
                mapper, semantic, codeGraph, mock(AgentTraceService.class));

        var findings = gate.evaluate(taskId, List.of(candidate), List.of(controller, serviceChunk));

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.getFilePath()).isEqualTo("demo/LabScenarioService.java");
            assertThat(finding.getStartLine()).isEqualTo(86);
            assertThat(finding.getEvidence())
                    .contains("[漏洞位置] demo/LabScenarioService.java:86")
                    .contains("[调用入口] demo/LabScenarioController.java:84");
        });
        assertThat(hypothesis.getPrimaryChunkId()).isEqualTo(2L);
        assertThat(hypothesis.getEvidenceChunkIds()).isEqualTo("2,1");
    }

    private CodeChunk chunk(UUID taskId, long id, AnalysisScope scope,
                            String file, int line, String content) {
        CodeChunk chunk = new CodeChunk(taskId, file, "Demo#run", null, line, line,
                content, "JAVA_METHOD", "String name", "", "search");
        chunk.setId(id);
        chunk.setAnalysisScope(scope);
        return chunk;
    }

    private AuditHypothesis hypothesis(UUID taskId, long primary) {
        return new AuditHypothesis(taskId, UUID.randomUUID(), VulnerabilityType.SQL_INJECTION,
                "外部输入进入动态查询", primary, String.valueOf(primary), Confidence.HIGH);
    }

    private LlmGateway.FindingProposal proposal(long primary, List<Long> evidence, int line) {
        return new LlmGateway.FindingProposal(VulnerabilityType.SQL_INJECTION,
                Severity.HIGH, Confidence.HIGH, "动态 SQL 注入", "外部输入进入动态查询",
                "使用参数化查询", primary, evidence, line, line);
    }
}
