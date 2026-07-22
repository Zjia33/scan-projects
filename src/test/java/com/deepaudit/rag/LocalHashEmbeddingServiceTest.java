package com.deepaudit.rag;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LocalHashEmbeddingServiceTest {

    private final LocalHashEmbeddingService service = new LocalHashEmbeddingService();

    @Test
    void embeddingIsDeterministicAndSerializable() {
        double[] first = service.embed("order payment amount signature");
        double[] second = service.embed("order payment amount signature");
        double[] restored = service.deserialize(service.serialize(first));

        assertThat(first).containsExactly(second);
        assertThat(restored).containsExactly(first);
        assertThat(first).hasSize(128);
    }
}
