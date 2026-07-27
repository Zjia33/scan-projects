package com.deepaudit.mapper;

import com.deepaudit.domain.SemanticMethodChange;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface SemanticMethodChangeMapper {
    int deleteByTaskId(@Param("taskId") UUID taskId);
    int insertBatch(@Param("changes") List<SemanticMethodChange> changes);
    List<SemanticMethodChange> findByTaskId(@Param("taskId") UUID taskId);
}
