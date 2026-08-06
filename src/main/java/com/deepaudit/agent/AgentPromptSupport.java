package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;

import java.util.List;
import java.util.Set;

final class AgentPromptSupport {
    private AgentPromptSupport() {
    }

    static LlmGateway.Target target(CodeChunk chunk, Set<VulnerabilityType> hints) {
        String content = chunk.getContent() == null ? "" : chunk.getContent();
        String baseContent = chunk.getBaseContent() == null ? "" : chunk.getBaseContent();
        return new LlmGateway.Target(chunk.getId(), chunk.getFilePath(), chunk.getSymbolName(),
                chunk.getEndpoint(), chunk.getChunkType(), chunk.getParameters(), chunk.getAnnotations(),
                chunk.getCalledSymbols(), numberedExcerpt(content, chunk.getStartLine(), 4_000),
                chunk.getChangeType().name(), chunk.getAnalysisScope().name(),
                baseContent.substring(0, Math.min(2_000, baseContent.length())),
                hints == null ? List.of() : List.copyOf(hints), chunk.getStartLine(), chunk.getEndLine());
    }

    private static String numberedExcerpt(String content, int startLine, int maxChars) {
        String[] lines = content.split("\\R", -1);
        StringBuilder excerpt = new StringBuilder();
        for (int index = 0; index < lines.length; index++) {
            String numbered = (startLine + index) + " | " + lines[index] + "\n";
            if (excerpt.length() + numbered.length() > maxChars) break;
            excerpt.append(numbered);
        }
        return excerpt.toString().stripTrailing();
    }
}
