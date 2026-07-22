package com.deepaudit.mapper;

import com.deepaudit.domain.SecurityFlow;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface SecurityFlowMapper {
    int deleteByTaskId(@Param("taskId") UUID taskId);
    int insertBatch(@Param("flows") List<SecurityFlow> flows);
    List<SecurityFlow> findByTaskId(@Param("taskId") UUID taskId);
    List<SecurityFlow> findByTaskAndChunk(@Param("taskId") UUID taskId, @Param("chunkId") Long chunkId);
}
