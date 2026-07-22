package com.deepaudit.mapper;

import com.deepaudit.domain.AuditHypothesis;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface AuditHypothesisMapper {
    int insert(AuditHypothesis hypothesis);
    int update(AuditHypothesis hypothesis);
    List<AuditHypothesis> findByTaskId(@Param("taskId") UUID taskId);
    int deleteByTaskId(@Param("taskId") UUID taskId);
}
