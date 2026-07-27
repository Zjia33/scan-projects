package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
public class EmbeddingCacheEntry {
    private String cacheKey; // 由待嵌入内容生成的缓存键
    private String embedding; // 缓存的向量序列化文本
    private Instant createdAt; // 缓存条目创建时间

    public EmbeddingCacheEntry(String cacheKey, String embedding) {
        this.cacheKey = cacheKey;
        this.embedding = embedding;
        this.createdAt = Instant.now();
    }

}
