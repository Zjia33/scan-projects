package com.deepaudit.mapper;

import com.deepaudit.domain.AuditTask;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface AuditTaskMapper {
    int insert(AuditTask task);
    AuditTask findById(@Param("id") UUID id);
    List<AuditTask> findAllOrderByCreatedAtDesc();
    List<AuditTask> findByProjectIdOrderByCreatedAtDesc(@Param("projectId") UUID projectId);
    int countActiveByProjectId(@Param("projectId") UUID projectId);
    int deleteByProjectId(@Param("projectId") UUID projectId);
    int updateWithVersion(AuditTask task);
}
