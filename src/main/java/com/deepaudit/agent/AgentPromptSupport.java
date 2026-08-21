package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.git.UnifiedChangeContext;

import java.util.List;
import java.util.Set;

final class AgentPromptSupport {
    private static final int CHANGE_CONTEXT_LINES = 5;
    private static final int MAX_CHANGE_CONTEXT_CHARS = 20_000;

    private AgentPromptSupport() {
    }

    static LlmGateway.Target target(CodeChunk chunk, Set<VulnerabilityType> hints) {
        return new LlmGateway.Target(chunk.getId(), chunk.getFilePath(), chunk.getSymbolName(),
                chunk.getEndpoint(), chunk.getChunkType(), chunk.getParameters(), chunk.getAnnotations(),
                chunk.getCalledSymbols(), changeContext(chunk),
                chunk.getChangeType().name(), chunk.getAnalysisScope().name(),
                "",
                hints == null ? List.of() : List.copyOf(hints), chunk.getStartLine(), chunk.getEndLine());
    }

    static String changeContext(CodeChunk chunk) {
        String base = chunk.getBaseContent() == null ? "" : chunk.getBaseContent();
        String target = chunk.getContent() == null ? "" : chunk.getContent();
        String diff = base.stripLeading().startsWith("@@ base ")
                ? base.strip()
                : UnifiedChangeContext.render(base, target, null, chunk.getStartLine(),
                CHANGE_CONTEXT_LINES, MAX_CHANGE_CONTEXT_CHARS, true);
        if (diff.isBlank()) return "[CHANGE_CONTEXT]\nNo textual change in this code chunk.";
        return "[CHANGE_CONTEXT]\n<UNTRUSTED_DIFF>\n" + diff + "\n</UNTRUSTED_DIFF>";
    }
}
