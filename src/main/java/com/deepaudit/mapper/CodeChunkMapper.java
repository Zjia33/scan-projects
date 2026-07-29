package com.deepaudit.mapper;

import com.deepaudit.domain.CodeChunk;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

// 定义 CodeChunkMapper 的数据库访问操作。
public interface CodeChunkMapper {
    // 从数据库查询 findByTaskId 对应的记录。
    List<CodeChunk> findByTaskId(@Param("taskId") UUID taskId);
    // 从数据库查询 findById 对应的记录。
    CodeChunk findById(@Param("id") Long id);
    // 从数据库查询 countByTaskId 对应的记录。
    long countByTaskId(@Param("taskId") UUID taskId);
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
    // 向数据库写入 insertBatch 对应的记录。
    int insertBatch(@Param("chunks") List<CodeChunk> chunks);
    // 更新数据库中 updateIncrementalMetadata 对应的记录。
    int updateIncrementalMetadata(CodeChunk chunk);
}
