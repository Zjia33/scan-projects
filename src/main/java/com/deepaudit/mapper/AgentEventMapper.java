package com.deepaudit.mapper;

import com.deepaudit.domain.AgentEvent;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface AgentEventMapper {
    int insert(AgentEvent event);
    List<AgentEvent> findByTaskId(@Param("taskId") UUID taskId);
    int deleteByTaskId(@Param("taskId") UUID taskId);
}
