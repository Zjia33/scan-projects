package com.deepaudit.rag;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@ConditionalOnProperty(name = "deepaudit.embedding.provider", havingValue = "remote")
public class RemoteEmbeddingService implements EmbeddingService {
    private static final int BATCH_SIZE = 32;
    private final RestClient restClient;
    private final String apiKey;
    private final String model;

    public RemoteEmbeddingService(@Value("${deepaudit.embedding.base-url}") String baseUrl,
                                  @Value("${deepaudit.embedding.api-key}") String apiKey,
                                  @Value("${deepaudit.embedding.model}") String model) {
        this.restClient = RestClient.builder().baseUrl(baseUrl).build();
        this.apiKey = apiKey;
        this.model = model;
    }

    @Override
    public double[] embed(String text) {
        return embedAll(List.of(text)).get(0);
    }

    @Override
    public List<double[]> embedAll(List<String> texts) {
        List<double[]> result = new ArrayList<>(texts.size());
        for (int start = 0; start < texts.size(); start += BATCH_SIZE) {
            result.addAll(request(texts.subList(start, Math.min(start + BATCH_SIZE, texts.size()))));
        }
        return result;
    }

    private List<double[]> request(List<String> input) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", model);
        body.put("input", input);
        RestClient.RequestBodySpec request = restClient.post().uri("/embeddings")
                .contentType(MediaType.APPLICATION_JSON);
        if (apiKey != null && !apiKey.isBlank()) {
            request.header("Authorization", "Bearer " + apiKey);
        }
        JsonNode response = request.body(body).retrieve().body(JsonNode.class);
        if (response == null || !response.path("data").isArray()) {
            throw new IllegalStateException("Embedding 服务返回格式错误");
        }
        List<JsonNode> rows = new ArrayList<>();
        response.path("data").forEach(rows::add);
        rows.sort(Comparator.comparingInt(node -> node.path("index").asInt()));
        if (rows.size() != input.size()) {
            throw new IllegalStateException("Embedding 返回数量与输入不一致");
        }
        return rows.stream().map(row -> {
            List<Double> values = new ArrayList<>();
            row.path("embedding").forEach(value -> values.add(value.asDouble()));
            return values.stream().mapToDouble(Double::doubleValue).toArray();
        }).toList();
    }

    @Override
    public String serialize(double[] vector) {
        return Arrays.stream(vector).mapToObj(Double::toString).collect(Collectors.joining(","));
    }

    @Override
    public double[] deserialize(String value) {
        if (value == null || value.isBlank()) return new double[0];
        return Arrays.stream(value.split(",")).mapToDouble(Double::parseDouble).toArray();
    }
}
