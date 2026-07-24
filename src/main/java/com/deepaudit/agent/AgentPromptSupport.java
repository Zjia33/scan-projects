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
                chunk.getCalledSymbols(), content.substring(0, Math.min(4_000, content.length())),
                chunk.getChangeType().name(), chunk.getAnalysisScope().name(),
                baseContent.substring(0, Math.min(2_000, baseContent.length())),
                hints == null ? List.of() : List.copyOf(hints));
    }
}
