package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class FindingConsolidatorTest {

    @Test
    void mergesValidatedResultsThatResolveToTheSameVulnerability() {
        UUID taskId = UUID.randomUUID();
        CodeChunk chunk = noticeChunk(taskId);
        Finding fromController = finding(taskId, VulnerabilityType.STORED_XSS,
                Severity.HIGH, Confidence.MEDIUM, 61, 62, "/notices/board",
                "控制器入口证据", FindingDeltaStatus.PERSISTING);
        Finding fromChangedService = finding(taskId, VulnerabilityType.STORED_XSS,
                Severity.CRITICAL, Confidence.HIGH, 61, 62, null,
                "服务方法变更证据", FindingDeltaStatus.NEW);
        fromController.setFingerprint("old-endpoint-sensitive-fingerprint");
        fromChangedService.setFingerprint("another-old-fingerprint");

        List<Finding> result = FindingConsolidator.consolidate(
                List.of(fromController, fromChangedService), List.of(chunk));

        assertThat(result).hasSize(1);
        Finding merged = result.get(0);
        assertThat(merged.getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(merged.getConfidence()).isEqualTo(Confidence.HIGH);
        assertThat(merged.getDeltaStatus()).isEqualTo(FindingDeltaStatus.NEW);
        assertThat(merged.getEndpoint()).isEqualTo("/notices/board");
        assertThat(merged.getEvidence()).contains("控制器入口证据", "服务方法变更证据");
        assertThat(merged.getFingerprint())
                .hasSize(64)
                .isNotEqualTo("old-endpoint-sensitive-fingerprint")
                .isNotEqualTo("another-old-fingerprint");
    }

    @Test
    void deduplicatesStructuredEvidenceBlocksWhenRelocatedFindingsMerge() {
        UUID taskId = UUID.randomUUID();
        CodeChunk chunk = noticeChunk(taskId);
        Finding first = finding(taskId, VulnerabilityType.STORED_XSS,
                Severity.HIGH, Confidence.HIGH, 61, 62, "/notices/board", """
                [CHUNK 2039] [漏洞位置] LabScenarioService.java:61-62
                service evidence

                [CHUNK 1986] [调用入口] LabScenarioController.java:61
                controller evidence
                """, FindingDeltaStatus.NEW);
        Finding duplicate = finding(taskId, VulnerabilityType.STORED_XSS,
                Severity.HIGH, Confidence.HIGH, 61, 62, "/notices/board", """
                [CHUNK 2039] [关联证据] LabScenarioService.java:61-62
                repeated service evidence

                [CHUNK 1986] [调用入口] LabScenarioController.java:61
                repeated controller evidence
                """, FindingDeltaStatus.NEW);

        Finding merged = FindingConsolidator.consolidate(
                List.of(first, duplicate), List.of(chunk)).get(0);

        assertThat(occurrences(merged.getEvidence(), "[CHUNK 2039]")).isEqualTo(1);
        assertThat(occurrences(merged.getEvidence(), "[CHUNK 1986]")).isEqualTo(1);
        assertThat(merged.getEvidence())
                .contains("[CHUNK 2039] [漏洞位置]")
                .doesNotContain("\n\n---\n\n");
    }

    @Test
    void mergesOverlappingValidatedRangesAndRebuildsFingerprintFromTheirUnion() {
        UUID taskId = UUID.randomUUID();
        CodeChunk chunk = noticeChunk(taskId);
        Finding first = finding(taskId, VulnerabilityType.STORED_XSS,
                Severity.HIGH, Confidence.HIGH, 61, 62, null,
                "标题拼接", FindingDeltaStatus.NEW);
        Finding second = finding(taskId, VulnerabilityType.STORED_XSS,
                Severity.HIGH, Confidence.HIGH, 62, 63, null,
                "内容输出", FindingDeltaStatus.NEW);

        List<Finding> result = FindingConsolidator.consolidate(List.of(first, second), List.of(chunk));

        assertThat(result).singleElement().satisfies(merged -> {
            assertThat(merged.getStartLine()).isEqualTo(61);
            assertThat(merged.getEndLine()).isEqualTo(63);
            assertThat(merged.getFingerprint()).hasSize(64);
        });
    }

    @Test
    void keepsNonOverlappingSinksInTheSameMethodSeparate() {
        UUID taskId = UUID.randomUUID();
        CodeChunk chunk = sqlChunk(taskId);
        Finding first = finding(taskId, VulnerabilityType.SQL_INJECTION,
                Severity.HIGH, Confidence.HIGH, 101, 101, "/search",
                "第一条查询", FindingDeltaStatus.NEW);
        Finding second = finding(taskId, VulnerabilityType.SQL_INJECTION,
                Severity.HIGH, Confidence.HIGH, 103, 103, "/search",
                "第二条查询", FindingDeltaStatus.NEW);
        first.setFilePath("src/main/java/demo/QueryService.java");
        second.setFilePath("src/main/java/demo/QueryService.java");

        List<Finding> result = FindingConsolidator.consolidate(List.of(first, second), List.of(chunk));

        assertThat(result).hasSize(2);
        assertThat(result).extracting(Finding::getFingerprint).doesNotHaveDuplicates();
    }

    @Test
    void mergesControllerAndServiceReportsFromTheSameVerifiedEvidenceChain() {
        UUID taskId = UUID.randomUUID();
        CodeChunk controller = new CodeChunk(taskId,
                "src/main/java/demo/SensitiveController.java", "SensitiveController#records",
                "/records/{id}", 30, 40, "return service.records(id);",
                "JAVA_METHOD", "Long id", "@GetMapping", "records");
        controller.setId(3708L);
        CodeChunk service = new CodeChunk(taskId,
                "src/main/java/demo/SensitiveService.java", "SensitiveService#records",
                null, 48, 52, "return repository.findWithSecrets(id);",
                "JAVA_METHOD", "Long id", "", "findWithSecrets");
        service.setId(3717L);
        Finding entryReport = finding(taskId, VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE,
                Severity.HIGH, Confidence.HIGH, 37, 37, "/records/{id}", """
                [CHUNK 3708] [调用入口] src/main/java/demo/SensitiveController.java:37
                return service.records(id);

                [CHUNK 3717] [漏洞位置] src/main/java/demo/SensitiveService.java:50
                return repository.findWithSecrets(id);
                """, FindingDeltaStatus.NEW);
        entryReport.setFilePath(controller.getFilePath());
        Finding sinkReport = finding(taskId, VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE,
                Severity.HIGH, Confidence.HIGH, 50, 50, null, """
                [CHUNK 3717] [漏洞位置] src/main/java/demo/SensitiveService.java:50
                return repository.findWithSecrets(id);
                """, FindingDeltaStatus.NEW);
        sinkReport.setFilePath(service.getFilePath());

        List<Finding> result = FindingConsolidator.consolidate(
                List.of(entryReport, sinkReport), List.of(controller, service));

        assertThat(result).singleElement().satisfies(merged -> {
            assertThat(merged.getFilePath()).isEqualTo(service.getFilePath());
            assertThat(merged.getStartLine()).isEqualTo(50);
            assertThat(merged.getEndpoint()).isEqualTo("/records/{id}");
            assertThat(occurrences(merged.getEvidence(), "[CHUNK 3717]")).isEqualTo(1);
        });
    }

    @Test
    void mergesEqualCrossLayerEvidenceAndKeepsTheRealEndpointBoundary() {
        UUID taskId = UUID.randomUUID();
        CodeChunk controller = new CodeChunk(taskId,
                "src/main/java/demo/AccountController.java", "AccountController#diagnostics",
                "/accounts/diagnostics", 40, 45, "return service.diagnostics(accountNo);",
                "JAVA_METHOD", "String accountNo", "@GetMapping", "diagnostics");
        controller.setId(3709L);
        CodeChunk service = new CodeChunk(taskId,
                "src/main/java/demo/AccountService.java", "AccountService#diagnostics",
                null, 53, 57, "return repository.diagnostics(accountNo);",
                "JAVA_METHOD", "String accountNo", "", "diagnostics");
        service.setId(3718L);
        String sharedEvidence = """
                [CHUNK 3709] [调用入口] src/main/java/demo/AccountController.java:43
                return service.diagnostics(accountNo);

                [CHUNK 3718] [关联证据] src/main/java/demo/AccountService.java:55
                return repository.diagnostics(accountNo);
                """;
        Finding controllerReport = finding(taskId, VulnerabilityType.AUTHORIZATION,
                Severity.HIGH, Confidence.HIGH, 43, 43, "/accounts/diagnostics",
                sharedEvidence, FindingDeltaStatus.NEW);
        controllerReport.setFilePath(controller.getFilePath());
        Finding serviceReport = finding(taskId, VulnerabilityType.AUTHORIZATION,
                Severity.HIGH, Confidence.HIGH, 55, 55, "/accounts/diagnostics",
                sharedEvidence, FindingDeltaStatus.NEW);
        serviceReport.setFilePath(service.getFilePath());

        Finding merged = FindingConsolidator.consolidate(
                List.of(serviceReport, controllerReport), List.of(controller, service)).get(0);

        assertThat(merged.getFilePath()).isEqualTo(controller.getFilePath());
        assertThat(merged.getStartLine()).isEqualTo(43);
    }

    @Test
    void mergesValidationReportsAcrossLayersAndKeepsConcreteServiceOperation() {
        UUID taskId = UUID.randomUUID();
        CodeChunk controller = new CodeChunk(taskId,
                "src/main/java/demo/LabScenarioController.java", "LabScenarioController#purchase",
                "/payments/purchase", 80, 85, "return service.purchase(request);",
                "JAVA_METHOD", "PurchaseRequest request", "@PostMapping", "purchase");
        controller.setId(4101L);
        CodeChunk service = new CodeChunk(taskId,
                "src/main/java/demo/LabScenarioService.java", "LabScenarioService#purchase",
                null, 78, 89, "BigDecimal total = request.quotedUnitPrice().multiply(quantity);",
                "JAVA_METHOD", "PurchaseRequest request", "", "multiply,debit");
        service.setId(4102L);
        String evidence = """
                [CHUNK 4101] [漏洞位置] src/main/java/demo/LabScenarioController.java:84
                return service.purchase(request);

                [CHUNK 4102] [漏洞位置] src/main/java/demo/LabScenarioService.java:86
                BigDecimal total = request.quotedUnitPrice().multiply(quantity);
                """;
        Finding entry = finding(taskId, VulnerabilityType.VALIDATION_BYPASS,
                Severity.HIGH, Confidence.HIGH, 84, 84, "/payments/purchase",
                evidence, FindingDeltaStatus.NEW);
        entry.setFilePath(controller.getFilePath());
        Finding operation = finding(taskId, VulnerabilityType.VALIDATION_BYPASS,
                Severity.HIGH, Confidence.HIGH, 86, 86, "/payments/purchase",
                evidence, FindingDeltaStatus.NEW);
        operation.setFilePath(service.getFilePath());

        Finding merged = FindingConsolidator.consolidate(
                List.of(entry, operation), List.of(controller, service)).get(0);

        assertThat(merged.getFilePath()).isEqualTo(service.getFilePath());
        assertThat(merged.getStartLine()).isEqualTo(86);
    }

    @Test
    void keepsCrossLayerFindingsWithOnlyPartiallyOverlappingEvidenceSeparate() {
        UUID taskId = UUID.randomUUID();
        Finding first = finding(taskId, VulnerabilityType.AUTHORIZATION,
                Severity.HIGH, Confidence.HIGH, 20, 20, "/first", """
                [CHUNK 100] [调用入口] FirstController.java:20
                first();
                [CHUNK 300] [关联证据] SharedService.java:50
                shared();
                """, FindingDeltaStatus.NEW);
        first.setFilePath("src/main/java/demo/FirstController.java");
        Finding second = finding(taskId, VulnerabilityType.AUTHORIZATION,
                Severity.HIGH, Confidence.HIGH, 30, 30, "/second", """
                [CHUNK 200] [调用入口] SecondController.java:30
                second();
                [CHUNK 300] [关联证据] SharedService.java:50
                shared();
                """, FindingDeltaStatus.NEW);
        second.setFilePath("src/main/java/demo/SecondController.java");

        assertThat(FindingConsolidator.consolidate(List.of(first, second), List.of())).hasSize(2);
    }

    private Finding finding(UUID taskId, VulnerabilityType type,
                            Severity severity, Confidence confidence,
                            int startLine, int endLine, String endpoint,
                            String evidence, FindingDeltaStatus deltaStatus) {
        Finding finding = new Finding(taskId, type, severity, confidence,
                "漏洞标题", "src/main/java/demo/LabScenarioService.java",
                startLine, endLine, endpoint,
                "漏洞描述", evidence, "修复建议");
        finding.setDeltaStatus(deltaStatus);
        return finding;
    }

    private CodeChunk noticeChunk(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId,
                "src/main/java/demo/LabScenarioService.java",
                "LabScenarioService#renderNoticeBoard", null,
                59, 64, """
                public String renderNoticeBoard() {
                    return noticeRepository.findAll().stream()
                            .map(notice -> "<h2>" + notice.title() + "</h2><div>"
                                    + notice.content() + "</div>")
                            .collect(Collectors.joining());
                }
                """, "JAVA_METHOD", "", "", "findAll,stream,map,collect");
        chunk.setId(2039L);
        return chunk;
    }

    private CodeChunk sqlChunk(UUID taskId) {
        CodeChunk chunk = new CodeChunk(taskId,
                "src/main/java/demo/QueryService.java",
                "QueryService#search", "/search",
                100, 104, """
                public void search(String first, String second) {
                    statement.execute("select * from a where id=" + first);
                    audit();
                    statement.execute("select * from b where id=" + second);
                }
                """, "JAVA_METHOD", "", "", "execute");
        chunk.setId(3001L);
        return chunk;
    }

    private int occurrences(String value, String token) {
        return (value.length() - value.replace(token, "").length()) / token.length();
    }
}
