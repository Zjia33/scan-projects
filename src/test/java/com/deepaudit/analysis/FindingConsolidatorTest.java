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
    void mergesCriticResultsThatRelocateToTheSameVulnerability() {
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
    void mergesOverlappingCriticRangesAndRebuildsFingerprintFromTheirUnion() {
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
