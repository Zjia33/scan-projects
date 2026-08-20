package com.deepaudit.agent;

import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.HypothesisStatus;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.semantic.SemanticEvidenceService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CriticAgentServiceTest {

    @Test
    void rebuildsCriticRequestWithCandidateAlignedContextAndRejectsUnknownCandidateId() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        String content = java.util.stream.IntStream.rangeClosed(100, 159)
                .mapToObj(line -> line == 130 ? "statement.execute(userSql);" : "line" + line + "();")
                .collect(java.util.stream.Collectors.joining("\n"));
        CodeChunk chunk = new CodeChunk(taskId, "QueryService.java", "QueryService#search", null,
                100, 159, content, "JAVA_METHOD", "String userSql", "", "execute");
        chunk.setId(3001L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "外部参数进入动态查询", "使用参数化查询",
                chunk.getId(), List.of(chunk.getId()), 130, 130);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.SQL_INJECTION, "动态查询候选", chunk.getId(),
                String.valueOf(chunk.getId()), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.SQL_INJECTION, proposal, "旧的四行证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(chunk.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, chunk.getId(), "search"));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "返回了本次请求未下发的候选", FindingDeltaStatus.NEW,
                chunk.getId(), 130, 130, "UNSAFE_QUERY_CONSTRUCTION", "DATA_ACCESS",
                "candidate-not-in-request", LlmGateway.CriticVerdict.CONFIRMED, List.of()));

        chunk.setAnalysisScope(com.deepaudit.domain.AnalysisScope.CHANGED);
        service.review(taskId, candidate, recon(), List.of(chunk));

        ArgumentCaptor<LlmGateway.CriticRequest> request = ArgumentCaptor.forClass(
                LlmGateway.CriticRequest.class);
        verify(gateway).critique(request.capture());
        assertThat(request.getValue().changeContext()).contains("[CHANGE_CONTEXT]");
        assertThat(request.getValue().evidence())
                .contains("[CRITIC_LOCATION_EVIDENCE]")
                .contains("[LOCATION_REF] candidateId=3001:130-130")
                .contains("    128 | line128();")
                .contains(">>>   130 | statement.execute(userSql);")
                .contains("    132 | line132();")
                .doesNotContain("旧的四行证据");
        assertThat(hypothesis.getStatus()).isEqualTo(HypothesisStatus.INSUFFICIENT_EVIDENCE);
    }

    @Test
    void limitsCriticLocationReferencesToThirtyAndFivePerChunk() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        List<CodeChunk> chunks = new java.util.ArrayList<>();
        for (int chunkIndex = 0; chunkIndex < 10; chunkIndex++) {
            StringBuilder source = new StringBuilder("public void run" + chunkIndex + "(Command command) {\n");
            for (int call = 0; call < 10; call++) {
                source.append("    validator.check").append(call).append("(command);\n");
            }
            source.append("}");
            CodeChunk chunk = new CodeChunk(taskId, "Service" + chunkIndex + ".java",
                    "Service" + chunkIndex + "#run", null, 100 + chunkIndex * 20,
                    111 + chunkIndex * 20, source.toString(), "JAVA_METHOD", "Command command", "", "check");
            chunk.setId(5_000L + chunkIndex);
            chunk.setAnalysisScope(chunkIndex == 0 ? AnalysisScope.CHANGED : AnalysisScope.CONTEXT);
            chunks.add(chunk);
        }
        CodeChunk primary = chunks.get(0);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.MEDIUM,
                "服务端校验可能被绕过", "变更入口到达多个校验和业务节点", "补充不可绕过的校验",
                primary.getId(), List.of(primary.getId()), primary.getStartLine() + 1,
                primary.getStartLine() + 1);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(), proposal.type(),
                proposal.title(), primary.getId(), String.valueOf(primary.getId()), Confidence.MEDIUM);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.VALIDATION_BYPASS, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(primary.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, primary.getId(), "run"));
        LinkedHashSet<Long> relatedIds = chunks.stream().skip(1).map(CodeChunk::getId)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        when(semanticEvidenceService.criticReviewContextIds(eq(taskId), anySet(), eq(3)))
                .thenReturn(relatedIds);
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                false, Confidence.LOW, "当前候选不足以确认绕过", FindingDeltaStatus.NEW,
                null, null, null, null, null, null,
                LlmGateway.CriticVerdict.INSUFFICIENT_EVIDENCE, List.of()));

        service.review(taskId, candidate, recon(), chunks);

        ArgumentCaptor<LlmGateway.CriticRequest> request =
                ArgumentCaptor.forClass(LlmGateway.CriticRequest.class);
        verify(gateway).critique(request.capture());
        List<LlmGateway.LocationCandidateRef> references = request.getValue().locationCandidates();
        assertThat(references).hasSize(30);
        assertThat(references.stream().collect(java.util.stream.Collectors.groupingBy(
                        LlmGateway.LocationCandidateRef::chunkId, java.util.stream.Collectors.counting())))
                .allSatisfy((chunkId, count) -> assertThat(count).isLessThanOrEqualTo(5));
        assertThat(references).allSatisfy(reference ->
                assertThat(request.getValue().evidence()).contains(reference.candidateId()));
    }

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
        CodeChunk debitRepository = debitRepository(taskId);
        LlmGateway.FindingProposal proposedAtController = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "服务端直接信任 quotedUnitPrice", "服务端查询可信价格",
                controller.getId(), List.of(controller.getId(), vulnerableService.getId(),
                        debitRepository.getId()), 82, 83);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.VALIDATION_BYPASS, "报价缺少服务端验证", controller.getId(),
                controller.getId() + "," + vulnerableService.getId(), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.VALIDATION_BYPASS, proposedAtController, "旧的候选证据文本", hypothesis);

        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(controller.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, controller.getId(), "purchase"));
        when(semanticEvidenceService.independentCriticEvidence(
                taskId, controller.getId(), VulnerabilityType.VALIDATION_BYPASS)).thenReturn("调用链证据");
        when(semanticEvidenceService.callSiteLines(eq(taskId), eq(vulnerableService.getId()), anySet()))
                .thenReturn(Map.of(controller.getId(), 84));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "实际风险发生在服务层扣款逻辑", FindingDeltaStatus.NEW,
                vulnerableService.getId(), 86, 88, "MISSING_VALIDATION", "BUSINESS_OPERATION", null,
                LlmGateway.CriticVerdict.CONFIRMED, List.of()));
        controller.setAnalysisScope(com.deepaudit.domain.AnalysisScope.CHANGED);

        Optional<Finding> result = service.review(taskId, candidate, recon(),
                List.of(controller, vulnerableService, debitRepository));

        assertThat(result).isPresent();
        Finding finding = result.orElseThrow();
        assertThat(finding.getFilePath()).isEqualTo("LabScenarioService.java");
        assertThat(finding.getStartLine()).isEqualTo(86);
        assertThat(finding.getEndLine()).isEqualTo(88);
        assertThat(finding.getLocationKind()).isEqualTo(
                com.deepaudit.domain.FindingLocationKind.RESPONSIBILITY_ANCHOR);
        assertThat(finding.getEndpoint()).isEqualTo("/payments/purchase");
        assertThat(finding.getEvidence())
                .contains("[责任锚点] LabScenarioService.java:86-88")
                .contains("[调用入口] LabScenarioController.java:84")
                .doesNotContain("旧的候选证据文本");
        assertThat(finding.getEvidence()).doesNotContain("AccountRepository.java");
        ArgumentCaptor<LlmGateway.CriticRequest> request =
                ArgumentCaptor.forClass(LlmGateway.CriticRequest.class);
        verify(gateway).critique(request.capture());
        assertThat(request.getValue().evidence()).contains("CHUNK_ID=" + debitRepository.getId());
        assertThat(hypothesis.getPrimaryChunkId()).isEqualTo(vulnerableService.getId());
        assertThat(hypothesis.getEvidenceChunkIds())
                .doesNotContain(String.valueOf(debitRepository.getId()));
        verify(traceService).event(eq(taskId), any(), eq(AgentType.CRITIC),
                eq(com.deepaudit.domain.AgentEventType.REASONING),
                eq("实际风险发生在服务层扣款逻辑"));
    }

    @Test
    void relocatesIneffectiveMethodSecurityFindingFromDataReadToSecurityBoundary() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk controller = noticeController(taskId);
        CodeChunk dataRead = noticeService(taskId);
        controller.setAnalysisScope(AnalysisScope.IMPACTED);
        dataRead.setAnalysisScope(AnalysisScope.CHANGED);
        LlmGateway.FindingProposal proposedAtDataRead = new LlmGateway.FindingProposal(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, Severity.HIGH, Confidence.HIGH,
                "方法级权限注解未生效", "项目未启用 @EnableGlobalMethodSecurity，@PreAuthorize 不生效",
                "启用方法级安全", dataRead.getId(), List.of(dataRead.getId(), controller.getId()), 60, 60);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, "公开接口暴露敏感公告", dataRead.getId(),
                dataRead.getId() + "," + controller.getId(), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.AUTHORIZATION, proposedAtDataRead, "候选证据", hypothesis);

        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(dataRead.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, dataRead.getId(), "renderNoticeBoard"));
        when(semanticEvidenceService.independentCriticEvidence(
                taskId, dataRead.getId(), VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE))
                .thenReturn("全局方法级安全配置缺失");
        when(semanticEvidenceService.callSiteLines(eq(taskId), eq(controller.getId()), anySet()))
                .thenReturn(Map.of());
        // 即使模型仍错误地选择数据读取行，服务端也必须按根因重定位到失效的权限注解。
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                true, Confidence.HIGH,
                "全局未启用 @EnableGlobalMethodSecurity，导致 @PreAuthorize 注解不生效",
                FindingDeltaStatus.PERSISTING, dataRead.getId(), 60, 60,
                "INEFFECTIVE_SECURITY_CONTROL", "DATA_ACCESS", null,
                LlmGateway.CriticVerdict.CONFIRMED, List.of()));

        Optional<Finding> result = service.review(taskId, candidate, recon(),
                List.of(controller, dataRead));

        assertThat(result).isPresent();
        Finding finding = result.orElseThrow();
        assertThat(finding.getFilePath()).isEqualTo("LabScenarioController.java");
        assertThat(finding.getStartLine()).isEqualTo(58);
        assertThat(finding.getEndLine()).isEqualTo(58);
        assertThat(finding.getEndpoint()).isEqualTo("/api/lab/notices/board");
        assertThat(finding.getDeltaStatus()).isEqualTo(FindingDeltaStatus.PERSISTING);
        assertThat(finding.getLocationKind()).isEqualTo(
                com.deepaudit.domain.FindingLocationKind.ROOT_CAUSE);
        assertThat(finding.getEvidence())
                .contains("[漏洞根因] LabScenarioController.java:58")
                .contains(">>>    58 | @PreAuthorize")
                .contains("[关联证据] LabScenarioService.java:60")
                .doesNotContain(">>>    60 |     return noticeRepository.findAll().stream()");
        assertThat(hypothesis.getPrimaryChunkId()).isEqualTo(controller.getId());
    }

    @Test
    void normalizesConfirmedPortOperationFromItsActualSourceRole() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk operation = customOperation(taskId);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "未验证指令被提交", "外部指令直接交给账本端口执行", "提交前验证金额与归属",
                operation.getId(), List.of(operation.getId()), 40, 40);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.VALIDATION_BYPASS, "指令缺少服务端验证", operation.getId(),
                String.valueOf(operation.getId()), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(AgentType.VALIDATION_BYPASS, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(operation.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, operation.getId(), "apply"));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "账本操作缺少服务端约束", FindingDeltaStatus.NEW,
                operation.getId(), 40, 40, "MISSING_VALIDATION", "BUSINESS_OPERATION", null,
                LlmGateway.CriticVerdict.CONFIRMED, List.of()));
        operation.setAnalysisScope(com.deepaudit.domain.AnalysisScope.CHANGED);
        Optional<Finding> result = service.review(taskId, candidate, recon(), List.of(operation));

        assertThat(result).get().satisfies(finding -> {
            assertThat(finding.getStartLine()).isEqualTo(41);
            assertThat(finding.getEndLine()).isEqualTo(41);
        });
        assertThat(hypothesis.getStatus()).isEqualTo(com.deepaudit.domain.HypothesisStatus.CONFIRMED);
        verify(gateway, never()).repairLocation(any());
    }

    @Test
    void treatsCandidateAsInsufficientWhenLocationRepairStillCannotResolve() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk operation = new CodeChunk(taskId, "CommandService.java", "CommandService#apply", null,
                40, 42, """
                public void apply(Command command) {
                    handler.apply(command);
                }
                """, "JAVA_METHOD", "Command command", "", "apply");
        operation.setId(2101L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "未验证指令被提交", "外部指令直接交给账本端口执行", "提交前验证金额与归属",
                operation.getId(), List.of(operation.getId()), 40, 40);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.VALIDATION_BYPASS, "指令缺少服务端验证", operation.getId(),
                String.valueOf(operation.getId()), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(AgentType.VALIDATION_BYPASS, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(operation.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, operation.getId(), "apply"));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "账本操作缺少服务端约束", FindingDeltaStatus.NEW,
                operation.getId(), 40, 40, "MISSING_VALIDATION", "BUSINESS_OPERATION", null,
                LlmGateway.CriticVerdict.CONFIRMED, List.of()));
        when(gateway.repairLocation(any())).thenReturn(
                new LlmGateway.LocationDecision("invented:1-1", "错误候选"));

        operation.setAnalysisScope(com.deepaudit.domain.AnalysisScope.CHANGED);
        Optional<Finding> result = service.review(taskId, candidate, recon(), List.of(operation));

        assertThat(result).isEmpty();
        assertThat(hypothesis.getStatus())
                .isEqualTo(com.deepaudit.domain.HypothesisStatus.INSUFFICIENT_EVIDENCE);
        assertThat(hypothesis.getCriticReason()).contains("未通过精确定位门禁", "定位修复未选择合法候选 ID")
                .doesNotContain("已确认漏洞");
        verify(hypothesisMapper).update(hypothesis);
        verify(gateway).repairLocation(any());
    }

    @Test
    void allowsActualContextLocationWhenIncrementalEvidenceContainsChangedCausalAnchor() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk changedEntry = controller(taskId);
        CodeChunk contextOperation = vulnerableService(taskId);
        changedEntry.setAnalysisScope(AnalysisScope.CHANGED);
        contextOperation.setAnalysisScope(AnalysisScope.CONTEXT);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "变更入口调用原有的不安全扣款操作", "服务端查询可信价格",
                changedEntry.getId(), List.of(changedEntry.getId(), contextOperation.getId()), 84, 84);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.VALIDATION_BYPASS, "变更入口暴露未验证操作", changedEntry.getId(),
                changedEntry.getId() + "," + contextOperation.getId(), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(AgentType.VALIDATION_BYPASS, proposal, "调用链证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(changedEntry.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, changedEntry.getId(), "purchase"));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "变更入口能够到达原有危险扣款逻辑", FindingDeltaStatus.NEW,
                contextOperation.getId(), 86, 88, "MISSING_VALIDATION", "BUSINESS_OPERATION", null,
                LlmGateway.CriticVerdict.CONFIRMED, List.of()));

        Optional<Finding> result = service.review(taskId, candidate, recon(),
                List.of(changedEntry, contextOperation));

        assertThat(result).get().satisfies(finding -> {
            assertThat(finding.getFilePath()).isEqualTo("LabScenarioService.java");
            assertThat(finding.getStartLine()).isEqualTo(86);
            assertThat(finding.getDeltaStatus()).isEqualTo(FindingDeltaStatus.NEW);
        });
        assertThat(hypothesis.getPrimaryChunkId()).isEqualTo(contextOperation.getId());
    }

    @Test
    void promotesVerifiedCallGraphReviewContextToLocationCandidates() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk changedEntry = customOperation(taskId);
        CodeChunk relatedOperation = vulnerableService(taskId);
        changedEntry.setAnalysisScope(AnalysisScope.CHANGED);
        relatedOperation.setAnalysisScope(AnalysisScope.CONTEXT);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "变更入口可到达未验证报价的扣款操作", "服务端查询可信价格",
                changedEntry.getId(), List.of(changedEntry.getId()), 41, 41);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(), proposal.type(),
                proposal.title(), changedEntry.getId(), String.valueOf(changedEntry.getId()), Confidence.HIGH);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.VALIDATION_BYPASS, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(changedEntry.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, changedEntry.getId(), "apply"));
        when(semanticEvidenceService.criticReviewContextIds(eq(taskId), anySet(), eq(3)))
                .thenReturn(Set.of(relatedOperation.getId()));
        when(gateway.critique(any())).thenAnswer(invocation -> {
            LlmGateway.CriticRequest request = invocation.getArgument(0);
            LlmGateway.LocationCandidateRef selected = request.locationCandidates().stream()
                    .filter(value -> value.chunkId() == relatedOperation.getId())
                    .findFirst().orElseThrow();
            assertThat(request.evidence()).contains("quotedUnitPrice", selected.candidateId());
            return new LlmGateway.CriticDecision(
                    true, Confidence.HIGH, "已验证调用链到达未重算报价的扣款操作", FindingDeltaStatus.NEW,
                    selected.chunkId(), selected.startLine(), selected.endLine(),
                    "MISSING_VALIDATION", "BUSINESS_OPERATION", selected.candidateId(),
                    LlmGateway.CriticVerdict.CONFIRMED, List.of());
        });

        Optional<Finding> result = service.review(
                taskId, candidate, recon(), List.of(changedEntry, relatedOperation));

        assertThat(result).get().satisfies(finding -> {
            assertThat(finding.getFilePath()).isEqualTo("LabScenarioService.java");
            assertThat(finding.getStartLine()).isEqualTo(86);
        });
        assertThat(hypothesis.getPrimaryChunkId()).isEqualTo(relatedOperation.getId());
    }

    @Test
    void keepsHypothesisAsInsufficientWhenCriticCannotReachAConclusion() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk operation = customOperation(taskId);
        operation.setAnalysisScope(AnalysisScope.CHANGED);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.MEDIUM,
                "未验证指令被提交", "当前证据尚未覆盖完整调用入口", "补充调用链",
                operation.getId(), List.of(operation.getId()), 41, 41);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                proposal.type(), proposal.title(), operation.getId(), String.valueOf(operation.getId()),
                Confidence.MEDIUM);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.VALIDATION_BYPASS, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(operation.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, operation.getId(), "apply"));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                false, Confidence.LOW, "缺少入口到危险操作的完整关系", FindingDeltaStatus.NEW,
                null, null, null, null, null, null,
                LlmGateway.CriticVerdict.INSUFFICIENT_EVIDENCE, List.of()));

        Optional<Finding> result = service.review(taskId, candidate, recon(), List.of(operation));

        assertThat(result).isEmpty();
        assertThat(hypothesis.getStatus())
                .isEqualTo(com.deepaudit.domain.HypothesisStatus.INSUFFICIENT_EVIDENCE);
        assertThat(hypothesis.getCriticReason()).contains("证据不足", "完整关系");
        verify(hypothesisMapper).update(hypothesis);
        verify(traceService, never()).event(eq(taskId), any(), eq(AgentType.CRITIC),
                eq(com.deepaudit.domain.AgentEventType.REASONING),
                eq("缺少入口到危险操作的完整关系"));
    }

    @Test
    void rejectsOnlyWhenCriticCitesVerifiedCounterEvidenceChunk() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk operation = customOperation(taskId);
        operation.setAnalysisScope(AnalysisScope.CHANGED);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.MEDIUM,
                "指令可能缺少验证", "需要核对账本调用前的验证逻辑", "增加验证",
                operation.getId(), List.of(operation.getId()), 41, 41);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                proposal.type(), proposal.title(), operation.getId(), String.valueOf(operation.getId()),
                Confidence.MEDIUM);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.VALIDATION_BYPASS, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(operation.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, operation.getId(), "apply"));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                false, Confidence.HIGH, "主证据代码块中已经执行完整服务端验证", FindingDeltaStatus.NEW,
                null, null, null, null, null, null, LlmGateway.CriticVerdict.REJECTED,
                List.of(operation.getId())));

        Optional<Finding> result = service.review(taskId, candidate, recon(), List.of(operation));

        assertThat(result).isEmpty();
        assertThat(hypothesis.getStatus()).isEqualTo(com.deepaudit.domain.HypothesisStatus.REJECTED);
        assertThat(hypothesis.getCriticReason()).contains("服务端验证");
    }

    @Test
    void doesNotRejectHypothesisWhenCriticResponseFormatRemainsInvalid() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk operation = customOperation(taskId);
        operation.setAnalysisScope(AnalysisScope.CHANGED);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.MEDIUM,
                "未验证指令被提交", "外部指令进入账本操作", "增加验证",
                operation.getId(), List.of(operation.getId()), 41, 41);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                proposal.type(), proposal.title(), operation.getId(), String.valueOf(operation.getId()),
                Confidence.MEDIUM);
        AgentCandidate candidate = new AgentCandidate(
                AgentType.VALIDATION_BYPASS, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(operation.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, operation.getId(), "apply"));
        when(gateway.critique(any())).thenThrow(
                new AiResponseFormatException("缺少 confirmed 和 reason", null));

        Optional<Finding> result = service.review(taskId, candidate, recon(), List.of(operation));

        assertThat(result).isEmpty();
        assertThat(hypothesis.getStatus())
                .isEqualTo(com.deepaudit.domain.HypothesisStatus.INSUFFICIENT_EVIDENCE);
        assertThat(hypothesis.getCriticReason()).contains("响应格式异常", "未执行漏洞否决");
        verify(traceService).event(eq(taskId), any(), eq(AgentType.CRITIC),
                eq(com.deepaudit.domain.AgentEventType.FORMAT_ERROR), any());
    }

    @Test
    void addsGlobalSecurityConfigurationAsReadOnlyCriticContext() {
        UUID taskId = UUID.randomUUID();
        LlmGateway gateway = mock(LlmGateway.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        SemanticEvidenceService semanticEvidenceService = mock(SemanticEvidenceService.class);
        CriticAgentService service = new CriticAgentService(
                gateway, traceService, hypothesisMapper, semanticEvidenceService);
        CodeChunk endpoint = controller(taskId);
        endpoint.setAnalysisScope(AnalysisScope.CHANGED);
        CodeChunk security = new CodeChunk(taskId, "SecurityConfig.java", "SecurityConfig#filterChain",
                null, 20, 25, """
                SecurityFilterChain filterChain(HttpSecurity http) {
                    return http.authorizeHttpRequests(auth -> auth
                            .requestMatchers("/payments/**").authenticated()).build();
                }
                """, "JAVA_METHOD", "HttpSecurity http", "", "requestMatchers,authenticated");
        security.setId(2200L);
        security.setAnalysisScope(AnalysisScope.CONTEXT);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.AUTHORIZATION, Severity.HIGH, Confidence.MEDIUM,
                "对象级授权缺失", "入口认证后可能未校验资源归属", "增加对象归属校验",
                endpoint.getId(), List.of(endpoint.getId()), 84, 84);
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(), proposal.type(),
                proposal.title(), endpoint.getId(), String.valueOf(endpoint.getId()), Confidence.MEDIUM);
        AgentCandidate candidate = new AgentCandidate(AgentType.AUTHORIZATION, proposal, "候选证据", hypothesis);
        when(traceService.start(eq(taskId), eq(AgentType.CRITIC), eq(endpoint.getId()), any()))
                .thenReturn(new AgentRun(taskId, AgentType.CRITIC, endpoint.getId(), "purchase"));
        when(gateway.critique(any())).thenReturn(new LlmGateway.CriticDecision(
                false, Confidence.LOW, "认证配置不能证明对象级授权", FindingDeltaStatus.NEW,
                null, null, null, null, null, null,
                LlmGateway.CriticVerdict.INSUFFICIENT_EVIDENCE, List.of()));

        service.review(taskId, candidate, recon(), List.of(endpoint, security));

        ArgumentCaptor<LlmGateway.CriticRequest> request =
                ArgumentCaptor.forClass(LlmGateway.CriticRequest.class);
        verify(gateway).critique(request.capture());
        assertThat(request.getValue().independentSemanticEvidence())
                .contains("CRITIC_REVIEW_CONTEXT_ONLY", "SecurityConfig.java", "requestMatchers");
        assertThat(request.getValue().locationCandidates())
                .noneMatch(location -> location.chunkId() == security.getId());
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

    private CodeChunk debitRepository(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId, "AccountRepository.java",
                "AccountRepository#debit", null, 40, 47, """
                public synchronized void debit(String accountNo, BigDecimal amount) {
                    requirePositiveAmount(amount);
                    AccountDto account = requireAccount(accountNo);
                    if (account.balance().compareTo(amount) < 0) {
                        throw new IllegalArgumentException("Insufficient balance");
                    }
                    accountsByNo.put(accountNo, withBalance(account, account.balance().subtract(amount)));
                }
                """, "JAVA_METHOD", "String accountNo, BigDecimal amount", "", "requireAccount,put");
        chunk.setId(1601L);
        return chunk;
    }

    private CodeChunk noticeController(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId, "LabScenarioController.java",
                "LabScenarioController#viewNoticeBoard", "/api/lab/notices/board", 58, 62, """
                @PreAuthorize("hasAuthority('NOTICE_READ')")
                @GetMapping(value = "/notices/board", produces = MediaType.TEXT_HTML_VALUE)
                public String viewNoticeBoard() {
                    return labScenarioService.renderNoticeBoard();
                }
                """, "JAVA_METHOD", "", "@PreAuthorize,@GetMapping", "renderNoticeBoard");
        chunk.setId(1822L);
        return chunk;
    }

    private CodeChunk noticeService(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId, "LabScenarioService.java",
                "LabScenarioService#renderNoticeBoard", null, 59, 64, """
                public String renderNoticeBoard() {
                    return noticeRepository.findAll().stream()
                            .map(notice -> notice.title() + notice.content())
                            .collect(Collectors.joining());
                }
                """, "JAVA_METHOD", "", "", "findAll,stream,map,collect");
        chunk.setId(1875L);
        return chunk;
    }

    private CodeChunk customOperation(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId, "LedgerService.java", "LedgerService#apply", null,
                40, 42, """
                public void apply(Command command) {
                    ledgerPort.apply(command);
                }
                """, "JAVA_METHOD", "Command command", "", "apply");
        chunk.setId(2100L);
        return chunk;
    }

    private LlmGateway.ReconInsight recon() {
        return new LlmGateway.ReconInsight("Spring MVC 银行业务",
                com.deepaudit.recon.TechnologyProfile.empty());
    }
}
