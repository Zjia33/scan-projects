package com.deepaudit.mapper;

import com.deepaudit.domain.SemanticCallEdge;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface SemanticCallEdgeMapper {
    int deleteByTaskId(@Param("taskId") UUID taskId);
    int insertBatch(@Param("edges") List<SemanticCallEdge> edges);
    List<SemanticCallEdge> findByTaskId(@Param("taskId") UUID taskId);
    List<SemanticCallEdge> findByCallerChunkId(@Param("taskId") UUID taskId, @Param("chunkId") Long chunkId);
}
