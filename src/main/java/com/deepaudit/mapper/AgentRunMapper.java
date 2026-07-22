package com.deepaudit.mapper;

import com.deepaudit.domain.AgentRun;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface AgentRunMapper {
    int insert(AgentRun run);
    int update(AgentRun run);
    List<AgentRun> findByTaskId(@Param("taskId") UUID taskId);
    int deleteByTaskId(@Param("taskId") UUID taskId);
}
