package com.deepaudit.mapper;

import com.deepaudit.domain.CodeChunk;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface CodeChunkMapper {
    List<CodeChunk> findByTaskId(@Param("taskId") UUID taskId);
    CodeChunk findById(@Param("id") Long id);
    long countByTaskId(@Param("taskId") UUID taskId);
    int deleteByTaskId(@Param("taskId") UUID taskId);
    int insertBatch(@Param("chunks") List<CodeChunk> chunks);
}
