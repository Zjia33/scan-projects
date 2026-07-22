package com.deepaudit.mapper;

import com.deepaudit.domain.Finding;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface FindingMapper {
    List<Finding> findByTaskIdOrderByRisk(@Param("taskId") UUID taskId);
    long countByTaskId(@Param("taskId") UUID taskId);
    int deleteByTaskId(@Param("taskId") UUID taskId);
    int insertBatch(@Param("findings") List<Finding> findings);
}
