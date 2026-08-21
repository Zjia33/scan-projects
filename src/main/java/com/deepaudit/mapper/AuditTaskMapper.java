package com.deepaudit.mapper;

import com.deepaudit.domain.AuditTask;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.time.Instant;
import java.util.UUID;

// 定义 AuditTaskMapper 的数据库访问操作。
public interface AuditTaskMapper {
    // 向数据库写入 insert 对应的记录。
    int insert(AuditTask task);
    // 从数据库查询 findById 对应的记录。
    AuditTask findById(@Param("id") UUID id);
    // 从数据库查询 findAllOrderByCreatedAtDesc 对应的记录。
    List<AuditTask> findAllOrderByCreatedAtDesc();
    // 从数据库查询 findByProjectIdOrderByCreatedAtDesc 对应的记录。
    List<AuditTask> findByProjectIdOrderByCreatedAtDesc(@Param("projectId") UUID projectId);
    // 从数据库查询 countActiveByProjectId 对应的记录。
    int countActiveByProjectId(@Param("projectId") UUID projectId);
    // 删除数据库中 deleteByProjectId 对应的记录。
    int deleteByProjectId(@Param("projectId") UUID projectId);
    // 更新数据库中 updateWithVersion 对应的记录。
    int updateWithVersion(AuditTask task);
    // 不依赖调用方持有的旧版本号，原子地把任意非终态任务切换为已取消。
    int cancelIfActive(@Param("id") UUID id, @Param("completedAt") Instant completedAt,
                       @Param("currentStage") String currentStage);
}
