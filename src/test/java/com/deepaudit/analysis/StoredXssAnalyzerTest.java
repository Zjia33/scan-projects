package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class StoredXssAnalyzerTest {

    @Test
    void detectsPersistedJavaHtmlOutputAndRespectsHtmlEncoding() {
        StoredXssAnalyzer analyzer = new StoredXssAnalyzer();
        CodeChunk unsafe = chunk("""
                return noticeRepository.findAll().stream()
                        .map(notice -> "<article><h2>" + notice.title() + "</h2><div>"
                                + notice.content() + "</div></article>")
                        .collect(Collectors.joining());
                """);
        CodeChunk encoded = chunk("""
                return noticeRepository.findAll().stream()
                        .map(notice -> "<article>" + HtmlUtils.htmlEscape(notice.content()) + "</article>")
                        .collect(Collectors.joining());
                """);

        List<FindingDraft> unsafeFindings = analyzer.analyze(
                new AnalysisContext(UUID.randomUUID(), null, List.of(unsafe)));
        List<FindingDraft> encodedFindings = analyzer.analyze(
                new AnalysisContext(UUID.randomUUID(), null, List.of(encoded)));

        assertThat(unsafeFindings).singleElement().satisfies(finding -> {
            assertThat(finding.type()).isEqualTo(VulnerabilityType.STORED_XSS);
            assertThat(finding.title()).contains("未经编码");
        });
        assertThat(encodedFindings).isEmpty();
    }

    private CodeChunk chunk(String content) {
        return new CodeChunk(UUID.randomUUID(), "LabScenarioService.java",
                "LabScenarioService#renderNoticeBoard", null, 59, 65, content,
                "JAVA_METHOD", "", "", "findAll,stream,map,collect");
    }
}
