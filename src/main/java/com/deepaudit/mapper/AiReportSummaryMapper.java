package com.deepaudit.mapper;

import com.deepaudit.domain.AiReportSummary;
import org.apache.ibatis.annotations.Param;

import java.util.UUID;

// 定义 AiReportSummaryMapper 的数据库访问操作。
public interface AiReportSummaryMapper {
    // 向数据库写入 insert 对应的记录。
    int insert(AiReportSummary summary);
    // 从数据库查询 findByTaskId 对应的记录。
    AiReportSummary findByTaskId(@Param("taskId") UUID taskId);
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
}
