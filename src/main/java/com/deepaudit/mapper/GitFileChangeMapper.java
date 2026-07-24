package com.deepaudit.mapper;

import com.deepaudit.domain.GitFileChange;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface GitFileChangeMapper {
    int deleteByTaskId(@Param("taskId") UUID taskId);
    int insertBatch(@Param("changes") List<GitFileChange> changes);
    List<GitFileChange> findByTaskId(@Param("taskId") UUID taskId);
}
