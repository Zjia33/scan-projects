package com.deepaudit.rag;

import java.util.List;

public interface EmbeddingService {
    double[] embed(String text);
    default List<double[]> embedAll(List<String> texts) {
        return texts.stream().map(this::embed).toList();
    }
    String serialize(double[] vector);
    double[] deserialize(String value);
}
