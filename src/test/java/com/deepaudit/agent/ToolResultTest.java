package com.deepaudit.agent;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ToolResultTest {

    @Test
    void exposesEvidenceIdsAndMarksAutomaticTextTruncation() {
        ToolResult result = new ToolResult("HEAD\n" + "x".repeat(25_000) + "\nTAIL_MARKER",
                Set.of(11L), Set.of(22L));

        assertThat(result.truncated()).isTrue();
        assertThat(result.text()).hasSizeLessThanOrEqualTo(ToolResult.MAX_TEXT_CHARS)
                .contains("TOOL_RESULT_TRUNCATED", "TAIL_MARKER");
        assertThat(result.observationText()).contains(
                "truncated=true",
                "evidenceChunkIds=[11]",
                "candidateChunkIds=[22]",
                "textChars=");
    }
}
