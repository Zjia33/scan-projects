package com.deepaudit.mapper;

import com.deepaudit.domain.SemanticCallEdge;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

// 定义 SemanticCallEdgeMapper 的数据库访问操作。
public interface SemanticCallEdgeMapper {
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
    // 向数据库写入 insertBatch 对应的记录。
    int insertBatch(@Param("edges") List<SemanticCallEdge> edges);
    // 从数据库查询 findByTaskId 对应的记录。
    List<SemanticCallEdge> findByTaskId(@Param("taskId") UUID taskId);
    // 从数据库查询 findByCallerChunkId 对应的记录。
    List<SemanticCallEdge> findByCallerChunkId(@Param("taskId") UUID taskId, @Param("chunkId") Long chunkId);
}
