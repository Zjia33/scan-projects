package com.deepaudit.rag;

import com.deepaudit.domain.EmbeddingCacheEntry;
import com.deepaudit.mapper.EmbeddingCacheMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EmbeddingCacheServiceTest {
    @Test
    void reusesSerializedEmbeddingForIdenticalInput() {
        EmbeddingCacheMapper mapper = mock(EmbeddingCacheMapper.class);
        Map<String, EmbeddingCacheEntry> storage = new LinkedHashMap<>();
        when(mapper.findByKeys(anyList())).thenAnswer(invocation -> {
            List<String> keys = invocation.getArgument(0);
            return keys.stream().map(storage::get).filter(java.util.Objects::nonNull).toList();
        });
        doAnswer(invocation -> {
            List<EmbeddingCacheEntry> entries = invocation.getArgument(0);
            entries.forEach(entry -> storage.put(entry.getCacheKey(), entry));
            return entries.size();
        }).when(mapper).insertBatch(anyList());

        AtomicInteger calls = new AtomicInteger();
        EmbeddingService embeddings = new EmbeddingService() {
            @Override
            public double[] embed(String text) {
                calls.incrementAndGet();
                return new double[]{text.length()};
            }

            @Override
            public List<double[]> embedAll(List<String> texts) {
                calls.incrementAndGet();
                List<double[]> result = new ArrayList<>();
                texts.forEach(text -> result.add(new double[]{text.length()}));
                return result;
            }

            @Override
            public String serialize(double[] vector) {
                return Arrays.toString(vector);
            }

            @Override
            public double[] deserialize(String value) {
                return new double[0];
            }
        };
        EmbeddingCacheService service = new EmbeddingCacheService(mapper, embeddings, "remote", "test-model");

        List<String> first = service.embedSerialized(List.of("same code", "same code"));
        List<String> second = service.embedSerialized(List.of("same code"));

        assertThat(first).containsExactly(second.get(0), second.get(0));
        assertThat(calls).hasValue(1);
        assertThat(storage).hasSize(1);
    }
}
