package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
public class EmbeddingCacheEntry {
    private String cacheKey;
    private String embedding;
    private Instant createdAt;

    public EmbeddingCacheEntry(String cacheKey, String embedding) {
        this.cacheKey = cacheKey;
        this.embedding = embedding;
        this.createdAt = Instant.now();
    }

}
