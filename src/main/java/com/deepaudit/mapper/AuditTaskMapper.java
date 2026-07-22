package com.deepaudit.mapper;

import com.deepaudit.domain.AuditTask;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface AuditTaskMapper {
    int insert(AuditTask task);
    AuditTask findById(@Param("id") UUID id);
    List<AuditTask> findAllOrderByCreatedAtDesc();
    int updateWithVersion(AuditTask task);
}
