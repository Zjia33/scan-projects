package com.deepaudit.rag;

import org.springframework.stereotype.Service;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 可离线调试的确定性向量。生产环境可替换成真实 Embedding API，而不影响上层 RAG。
 */
@Service
@ConditionalOnProperty(name = "deepaudit.embedding.provider", havingValue = "local", matchIfMissing = true)
public class LocalHashEmbeddingService implements EmbeddingService {

    private static final int DIMENSIONS = 128;
    private static final Pattern TOKEN_SPLITTER = Pattern.compile("[^\\p{L}\\p{N}_$]+");

    @Override
    public double[] embed(String text) {
        double[] vector = new double[DIMENSIONS];
        for (String token : TOKEN_SPLITTER.split(text.toLowerCase(Locale.ROOT))) {
            if (token.isBlank()) {
                continue;
            }
            int hash = token.hashCode();
            int index = Math.floorMod(hash, DIMENSIONS);
            vector[index] += (hash & 1) == 0 ? 1.0 : -1.0;
        }
        double length = Math.sqrt(Arrays.stream(vector).map(value -> value * value).sum());
        if (length > 0) {
            for (int index = 0; index < vector.length; index++) {
                vector[index] /= length;
            }
        }
        return vector;
    }

    @Override
    public String serialize(double[] vector) {
        return Arrays.stream(vector).mapToObj(Double::toString).collect(Collectors.joining(","));
    }

    @Override
    public double[] deserialize(String value) {
        if (value == null || value.isBlank()) {
            return new double[DIMENSIONS];
        }
        return Arrays.stream(value.split(",")).mapToDouble(Double::parseDouble).toArray();
    }
}
