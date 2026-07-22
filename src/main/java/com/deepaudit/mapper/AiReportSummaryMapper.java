package com.deepaudit.mapper;

import com.deepaudit.domain.AiReportSummary;
import org.apache.ibatis.annotations.Param;

import java.util.UUID;

public interface AiReportSummaryMapper {
    int insert(AiReportSummary summary);
    AiReportSummary findByTaskId(@Param("taskId") UUID taskId);
    int deleteByTaskId(@Param("taskId") UUID taskId);
}
