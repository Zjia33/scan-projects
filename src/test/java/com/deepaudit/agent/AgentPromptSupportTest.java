package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AgentPromptSupportTest {

    @Test
    void removesMethodHeadLinesAlreadyPresentInTriageChangeWindows() {
        UUID taskId = UUID.randomUUID();
        String targetContent = """
                @PreAuthorize("hasAuthority('ORDER_READ')")
                public Order load(String input) {
                    validate(input);
                    return repository.find(input);
                }
                """;
        String baseContent = """
                @PreAuthorize("hasAuthority('ORDER_READ')")
                public Order load(String input) {
                    validateLegacy(input);
                    return repository.find(input);
                }
                """;
        CodeChunk chunk = new CodeChunk(taskId, "OrderService.java", "OrderService#load", null,
                10, 14, targetContent, "JAVA_METHOD", "String input",
                "@PreAuthorize", "validate,find");
        chunk.setId(7L);
        chunk.setBaseContent(baseContent);
        String targetChangeExcerpt = """
                [CHANGE_RANGE 10:11]
                10 | @PreAuthorize("hasAuthority('ORDER_READ')")
                11 | public Order load(String input) {
                [WINDOW_TRUNCATED]
                """;
        String baseChangeExcerpt = """
                [CHANGE_RANGE 10:11]
                10 | @PreAuthorize("hasAuthority('ORDER_READ')")
                11 | public Order load(String input) {
                [WINDOW_TRUNCATED]
                """;

        LlmGateway.Target target = AgentPromptSupport.target(chunk,
                Set.of(VulnerabilityType.AUTHORIZATION), baseChangeExcerpt, targetChangeExcerpt);

        assertThat(target.codeExcerpt())
                .startsWith("[与 Triage Target 变更窗口重复的行已省略]")
                .doesNotContain("10 | @PreAuthorize", "11 | public Order load")
                .contains("12 |     validate(input);", "13 |     return repository.find(input);");
        assertThat(target.baseCodeExcerpt())
                .startsWith("[与 Triage Base 变更窗口重复的行已省略]")
                .doesNotContain("@PreAuthorize", "public Order load")
                .contains("validateLegacy(input);", "return repository.find(input);");
    }

    @Test
    void keepsOriginalMethodHeadWhenTriageWindowDoesNotOverlap() {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "OrderService.java", "OrderService#load", null,
                10, 12, "annotation();\nvalidate();\nreturn value;", "JAVA_METHOD",
                "", "", "");
        chunk.setId(8L);
        chunk.setBaseContent("oldAnnotation();\noldValidate();\nreturn oldValue;");

        LlmGateway.Target target = AgentPromptSupport.target(chunk, Set.of(),
                "80 | unrelatedBase();", "80 | unrelatedTarget();");

        assertThat(target.codeExcerpt()).isEqualTo("10 | annotation();\n11 | validate();\n12 | return value;");
        assertThat(target.baseCodeExcerpt())
                .isEqualTo("oldAnnotation();\noldValidate();\nreturn oldValue;");
    }

    @Test
    void keepsTargetLineWhenTriageContainsOnlyItsTruncatedPrefix() {
        String longLine = "BEGIN_LONG_LINE_" + "x".repeat(5_000) + "_END_LONG_LINE";
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "OrderService.java", "OrderService#load", null,
                20, 20, longLine, "JAVA_METHOD", "", "", "");
        chunk.setId(9L);

        LlmGateway.Target target = AgentPromptSupport.target(chunk, Set.of(), "",
                "[CHANGE_RANGE 20:20]\n20 | " + longLine.substring(0, 1_000) + "\n[WINDOW_TRUNCATED]");

        assertThat(target.codeExcerpt())
                .startsWith("20 | BEGIN_LONG_LINE_")
                .doesNotContain("重复的行已省略");
    }
}
