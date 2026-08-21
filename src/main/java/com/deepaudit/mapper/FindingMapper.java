package com.deepaudit.mapper;

import com.deepaudit.domain.Finding;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

// 定义 FindingMapper 的数据库访问操作。
public interface FindingMapper {
    // 从数据库查询 findByTaskIdOrderByRisk 对应的记录。
    List<Finding> findByTaskIdOrderByRisk(@Param("taskId") UUID taskId);
    // 从数据库查询 countByTaskId 对应的记录。
    long countByTaskId(@Param("taskId") UUID taskId);
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
    // 向数据库写入 insertBatch 对应的记录。
    int insertBatch(@Param("findings") List<Finding> findings);
}
