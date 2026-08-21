package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphClient;
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.codegraph.CodeGraphResultMapper;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.recon.ReconService;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CodeGraphSymbolSearchServiceTest {
    @Test
    void materializesUnloadedQueryLocationsAndRefreshesAgentChunks() {
        UUID taskId = UUID.randomUUID();
        Path targetRoot = Path.of("target-root");
        CodeChunk current = chunk(taskId, 1L, "src/Controller.java", "Controller#entry", 1, 8);
        CodeChunk discovered = chunk(taskId, 2L, "src/OrderService.java", "OrderService#load", 7, 15);
        List<CodeChunk> sessionChunks = new ArrayList<>(List.of(current));
        CodeGraphClient.CodeGraphLocation location = new CodeGraphClient.CodeGraphLocation(
                "OrderService.load", "method", "src/OrderService.java", 7);

        CodeGraphIntegrationService codeGraph = mock(CodeGraphIntegrationService.class);
        ReconService recon = mock(ReconService.class);
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        when(codeGraph.querySymbols(taskId, "OrderService.load", "method", 100))
                .thenReturn(new CodeGraphIntegrationService.SymbolQueryResult(
                        true, false, List.of(location), targetRoot, ""));
        when(recon.materializeCodeGraphLocations(taskId, targetRoot, List.of(location))).thenReturn(1);
        when(mapper.findByTaskId(taskId)).thenReturn(List.of(current, discovered));
        CodeGraphSymbolSearchService service = new CodeGraphSymbolSearchService(
                codeGraph, new CodeGraphResultMapper(), recon, mapper);

        CodeGraphSymbolSearchService.Expansion result = service.expand(taskId,
                ToolArguments.of(Map.of("symbol", "OrderService#load", "kind", "JAVA_METHOD")),
                sessionChunks);

        assertThat(sessionChunks).extracting(CodeChunk::getId).containsExactly(1L, 2L);
        assertThat(result.note()).contains("locations=1", "mappedChunkIds=1", "materializedChunks=1",
                "unmappedLocations=0");
        verify(recon).materializeCodeGraphLocations(taskId, targetRoot, List.of(location));
    }

    @Test
    void keepsLocalResultButMarksCodeGraphFailureAsPartial() {
        CodeGraphSymbolSearchService.Expansion expansion = new CodeGraphSymbolSearchService.Expansion(
                true, true, "[CODEGRAPH_QUERY status=ERROR]");
        ToolResult local = new ToolResult("[SEARCH_RESULT] CHUNK_ID=1", java.util.Set.of(1L), java.util.Set.of());

        ToolResult merged = expansion.merge(local);

        assertThat(merged.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(merged.code()).isEqualTo("PARTIAL_RESULT");
        assertThat(merged.text()).contains("SEARCH_RESULT", "CODEGRAPH_QUERY status=ERROR");
    }

    private CodeChunk chunk(UUID taskId, long id, String path, String symbol, int start, int end) {
        CodeChunk chunk = new CodeChunk(taskId, path, symbol, null, start, end,
                "return ok();", "JAVA_METHOD", "", "", "");
        chunk.setId(id);
        return chunk;
    }
}
