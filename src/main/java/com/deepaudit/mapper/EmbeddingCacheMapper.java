package com.deepaudit.mapper;

import com.deepaudit.domain.EmbeddingCacheEntry;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface EmbeddingCacheMapper {
    List<EmbeddingCacheEntry> findByKeys(@Param("keys") List<String> keys);
    int insertBatch(@Param("entries") List<EmbeddingCacheEntry> entries);
}
