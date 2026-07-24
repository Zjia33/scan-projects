package com.deepaudit.rag;

import com.deepaudit.domain.EmbeddingCacheEntry;
import com.deepaudit.mapper.EmbeddingCacheMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class EmbeddingCacheService {
    private final EmbeddingCacheMapper mapper;
    private final EmbeddingService embeddingService;
    private final String namespace;

    @Autowired
    public EmbeddingCacheService(EmbeddingCacheMapper mapper, EmbeddingService embeddingService,
                                 @Value("${deepaudit.embedding.provider:local}") String provider,
                                 @Value("${deepaudit.embedding.model:local}") String model,
                                 @Value("${deepaudit.embedding.dimensions:128}") int dimensions) {
        this.mapper = mapper;
        this.embeddingService = embeddingService;
        this.namespace = provider + "|" + model + "|" + dimensions + "|";
    }

    public EmbeddingCacheService(EmbeddingCacheMapper mapper, EmbeddingService embeddingService,
                                 String provider, String model) {
        this(mapper, embeddingService, provider, model, -1);
    }

    // 按模型命名空间和完整输入哈希复用向量，避免未变化 Git Blob 重复调用远程服务。
    public List<String> embedSerialized(List<String> inputs) {
        if (inputs.isEmpty()) return List.of();
        List<String> keys = inputs.stream().map(this::key).toList();
        Map<String, String> values = new LinkedHashMap<>();
        for (int start = 0; start < keys.size(); start += 500) {
            mapper.findByKeys(keys.subList(start, Math.min(start + 500, keys.size())))
                    .forEach(entry -> values.put(entry.getCacheKey(), entry.getEmbedding()));
        }
        Map<String, String> missingInputs = new LinkedHashMap<>();
        for (int index = 0; index < keys.size(); index++) {
            if (!values.containsKey(keys.get(index))) missingInputs.putIfAbsent(keys.get(index), inputs.get(index));
        }
        if (!missingInputs.isEmpty()) {
            List<String> missingKeys = new ArrayList<>(missingInputs.keySet());
            List<double[]> vectors = embeddingService.embedAll(new ArrayList<>(missingInputs.values()));
            if (vectors.size() != missingKeys.size()) throw new IllegalStateException("Embedding 缓存回填数量不一致");
            List<EmbeddingCacheEntry> entries = new ArrayList<>();
            for (int index = 0; index < vectors.size(); index++) {
                String serialized = embeddingService.serialize(vectors.get(index));
                values.put(missingKeys.get(index), serialized);
                entries.add(new EmbeddingCacheEntry(missingKeys.get(index), serialized));
            }
            for (int start = 0; start < entries.size(); start += 300) {
                mapper.insertBatch(entries.subList(start, Math.min(start + 300, entries.size())));
            }
        }
        return keys.stream().map(values::get).toList();
    }

    private String key(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((namespace + input).getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("无法计算 Embedding 缓存键", exception);
        }
    }
}
