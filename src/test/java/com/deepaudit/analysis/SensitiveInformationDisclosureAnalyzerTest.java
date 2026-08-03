package com.deepaudit.analysis;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.GitFileChangeMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SensitiveInformationDisclosureAnalyzerTest {

    @Test
    void createsRedactedHintForHardcodedPasswordOnChangedTargetLine() {
        UUID taskId = UUID.randomUUID();
        GitFileChangeMapper mapper = mock(GitFileChangeMapper.class);
        when(mapper.findByTaskId(taskId)).thenReturn(List.of(change(taskId, "3:3")));
        CodeChunk chunk = configurationChunk(taskId, """
                spring:
                  datasource:
                    password: root123
                    username: application
                """);

        List<FindingDraft> findings = new SensitiveInformationDisclosureAnalyzer(mapper)
                .analyze(new AnalysisContext(taskId, Path.of("."), List.of(chunk)));

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.type()).isEqualTo(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE);
            assertThat(finding.startLine()).isEqualTo(3);
            assertThat(finding.description()).contains("密码");
            assertThat(finding.evidence()).contains("<REDACTED_LITERAL>").doesNotContain("root123");
        });
    }

    @Test
    void ignoresEnvironmentPlaceholderAndUnchangedLiteralButFlagsHardcodedFallback() {
        UUID taskId = UUID.randomUUID();
        GitFileChangeMapper mapper = mock(GitFileChangeMapper.class);
        when(mapper.findByTaskId(taskId)).thenReturn(List.of(change(taskId, "1:2")));
        CodeChunk chunk = configurationChunk(taskId, """
                jwt.secret: ${JWT_SECRET}
                jwt.refresh-token: ${REFRESH_TOKEN:committed-default}
                spring.datasource.password: historical-password
                """);

        List<FindingDraft> findings = new SensitiveInformationDisclosureAnalyzer(mapper)
                .analyze(new AnalysisContext(taskId, Path.of("."), List.of(chunk)));

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.startLine()).isEqualTo(2);
            assertThat(finding.evidence()).doesNotContain("committed-default", "historical-password");
        });
    }

    @Test
    void keepsPublicSensitiveResponseAsDisclosureWithoutRoutingItToAuthorization() {
        UUID taskId = UUID.randomUUID();
        GitFileChangeMapper mapper = mock(GitFileChangeMapper.class);
        when(mapper.findByTaskId(taskId)).thenReturn(List.of());
        CodeChunk chunk = new CodeChunk(taskId, "src/main/java/demo/PublicController.java",
                "PublicController#profile", "/public/profile", 10, 12,
                "return new Profile(user.password, user.idCard);", "JAVA_METHOD", "", "@GetMapping", "");
        chunk.setId(2L);
        chunk.setAnalysisScope(AnalysisScope.IMPACTED);

        List<FindingDraft> findings = new SensitiveInformationDisclosureAnalyzer(mapper)
                .analyze(new AnalysisContext(taskId, Path.of("."), List.of(chunk)));

        assertThat(findings).singleElement()
                .extracting(FindingDraft::type)
                .isEqualTo(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE);
    }

    private GitFileChange change(UUID taskId, String newRanges) {
        return new GitFileChange(taskId, "src/main/resources/application.yml",
                "src/main/resources/application.yml", "MODIFY", 1, 1,
                "", newRanges, "", true);
    }

    private CodeChunk configurationChunk(UUID taskId, String content) {
        int endLine = content.split("\\R", -1).length;
        CodeChunk chunk = new CodeChunk(taskId, "src/main/resources/application.yml",
                "application.yml#part-1", null, 1, endLine, content,
                "TEXT_YML", "", "", "");
        chunk.setId(1L);
        chunk.setAnalysisScope(AnalysisScope.CHANGED);
        return chunk;
    }
}
