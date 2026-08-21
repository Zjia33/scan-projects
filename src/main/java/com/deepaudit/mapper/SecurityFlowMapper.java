package com.deepaudit.mapper;

import com.deepaudit.domain.SecurityFlow;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

// 定义 SecurityFlowMapper 的数据库访问操作。
public interface SecurityFlowMapper {
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
    // 向数据库写入 insertBatch 对应的记录。
    int insertBatch(@Param("flows") List<SecurityFlow> flows);
    // 从数据库查询 findByTaskId 对应的记录。
    List<SecurityFlow> findByTaskId(@Param("taskId") UUID taskId);
    // 从数据库查询 findByTaskAndChunk 对应的记录。
    List<SecurityFlow> findByTaskAndChunk(@Param("taskId") UUID taskId, @Param("chunkId") Long chunkId);
}
