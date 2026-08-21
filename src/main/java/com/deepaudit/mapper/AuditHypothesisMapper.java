package com.deepaudit.mapper;

import com.deepaudit.domain.AuditHypothesis;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

// 定义 AuditHypothesisMapper 的数据库访问操作。
public interface AuditHypothesisMapper {
    // 向数据库写入 insert 对应的记录。
    int insert(AuditHypothesis hypothesis);
    // 更新数据库中 update 对应的记录。
    int update(AuditHypothesis hypothesis);
    // 从数据库查询 findByTaskId 对应的记录。
    List<AuditHypothesis> findByTaskId(@Param("taskId") UUID taskId);
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
}
