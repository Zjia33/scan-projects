package com.deepaudit.mapper;

import com.deepaudit.domain.GitFileChange;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

// 定义 GitFileChangeMapper 的数据库访问操作。
public interface GitFileChangeMapper {
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
    // 向数据库写入 insertBatch 对应的记录。
    int insertBatch(@Param("changes") List<GitFileChange> changes);
    // 从数据库查询 findByTaskId 对应的记录。
    List<GitFileChange> findByTaskId(@Param("taskId") UUID taskId);
}
