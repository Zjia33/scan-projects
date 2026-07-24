package com.deepaudit.rag;

import com.deepaudit.domain.CodeChunk;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryVectorRecallStoreTest {

    private final LocalHashEmbeddingService embeddingService = new LocalHashEmbeddingService();
    private final InMemoryVectorRecallStore store = new InMemoryVectorRecallStore(embeddingService);

    @Test
    void ranksVectorsByCosineSimilarityAndExcludesCurrentChunk() {
        UUID taskId = UUID.randomUUID();
        double[] query = embeddingService.embed("authorization owner permission");
        CodeChunk current = chunk(1L, taskId, "authorization owner permission");
        CodeChunk related = chunk(2L, taskId, "authorization owner validation");
        CodeChunk unrelated = chunk(3L, taskId, "css color margin");

        List<VectorRecallStore.VectorMatch> matches = store.search(
                List.of(current, related, unrelated), taskId, current.getId(), query, 10);

        assertThat(matches).extracting(VectorRecallStore.VectorMatch::chunkId)
                .containsExactly(2L, 3L);
        assertThat(matches.get(0).cosineSimilarity())
                .isGreaterThan(matches.get(1).cosineSimilarity());
    }

    private CodeChunk chunk(long id, UUID taskId, String text) {
        CodeChunk chunk = new CodeChunk(taskId, "Demo.java", "Demo#method", null,
                1, 2, text, embeddingService.serialize(embeddingService.embed(text)));
        chunk.setId(id);
        return chunk;
    }
}
