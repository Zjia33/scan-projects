package com.deepaudit.rag;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.mapper.CodeChunkMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RagServiceTest {

    @Test
    void usesVectorStoreForRecallAndKeepsHybridReranking() {
        UUID taskId = UUID.randomUUID();
        CodeChunk current = chunk(1L, taskId, "Controller#read", "/orders/{id}",
                "return service.load(id)", "load");
        CodeChunk candidate = chunk(2L, taskId, "OrderService#load", null,
                "repository.findById(id)", "findById");
        EmbeddingService embeddings = mock(EmbeddingService.class);
        VectorRecallStore vectorStore = mock(VectorRecallStore.class);
        when(embeddings.embed("load order")).thenReturn(new double[]{1, 0});
        when(vectorStore.search(anyList(), eq(taskId), eq(1L), any(double[].class), anyInt()))
                .thenReturn(List.of(new VectorRecallStore.VectorMatch(2L, 0.9)));
        RagService service = new RagService(mock(CodeChunkMapper.class), embeddings, vectorStore);

        List<RagService.RetrievedCode> results = service.retrieveDetailed(
                List.of(current, candidate),
                new RagService.RetrievalRequest(taskId, 1L, "load order",
                        current.getEndpoint(), current.getFilePath(), Set.of("load"), 5));

        assertThat(results).extracting(item -> item.chunk().getId()).containsExactly(2L);
        assertThat(results.get(0).reason()).contains("语义相似", "符号匹配");
        verify(vectorStore).search(anyList(), eq(taskId), eq(1L), any(double[].class), anyInt());
        verify(embeddings, never()).deserialize(any());
    }

    private CodeChunk chunk(long id, UUID taskId, String symbol, String endpoint,
                            String content, String calledSymbols) {
        CodeChunk chunk = new CodeChunk(taskId, "demo/Source.java", symbol, endpoint,
                1, 5, content, "", "JAVA_METHOD", "Long id", "", calledSymbols);
        chunk.setId(id);
        return chunk;
    }
}
