package com.deepaudit.agent;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class FindingFingerprintTest {

    @Test
    void ignoresEndpointAndWhitespaceButRetainsTheConfirmedCodeAnchor() {
        CodeChunk throughController = chunk("/notices/board", """
                public String renderNoticeBoard() {
                    return "<h2>" + notice.title()
                            + notice.content();
                }
                """);
        CodeChunk throughService = chunk(null, """
                public String renderNoticeBoard() {
                  return "<h2>" + notice.title()
                    + notice.content();
                }
                """);

        String first = FindingFingerprint.create(
                VulnerabilityType.STORED_XSS, throughController, 60, 61);
        String second = FindingFingerprint.create(
                VulnerabilityType.STORED_XSS, throughService, 60, 61);

        assertThat(first).isEqualTo(second).hasSize(64);
    }

    @Test
    void distinguishesDifferentSinksInsideTheSameMethod() {
        CodeChunk chunk = chunk(null, """
                public void search(String first, String second) {
                    statement.execute("select * from a where id=" + first);
                    audit();
                    statement.execute("select * from b where id=" + second);
                }
                """);

        String first = FindingFingerprint.create(
                VulnerabilityType.SQL_INJECTION, chunk, 60, 60);
        String second = FindingFingerprint.create(
                VulnerabilityType.SQL_INJECTION, chunk, 62, 62);

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void distinguishesRepeatedIdenticalSinkStatementsByOccurrence() {
        CodeChunk chunk = chunk(null, """
                public void search(String input) {
                    statement.execute(input);
                    statement.execute(input);
                    statement.execute(input);
                }
                """);

        String first = FindingFingerprint.create(
                VulnerabilityType.SQL_INJECTION, chunk, 60, 60);
        String second = FindingFingerprint.create(
                VulnerabilityType.SQL_INJECTION, chunk, 61, 61);

        assertThat(first).isNotEqualTo(second);
    }

    private CodeChunk chunk(String endpoint, String content) {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(),
                "src/main/java/demo/LabScenarioService.java",
                "LabScenarioService#renderNoticeBoard", endpoint,
                59, 63, content, "JAVA_METHOD", "", "", "");
        chunk.setId(100L);
        return chunk;
    }
}
