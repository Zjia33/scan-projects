package com.deepaudit.mapper;

import com.deepaudit.domain.Project;
import org.apache.ibatis.annotations.Param;

import java.util.UUID;
import java.util.List;
import java.time.Instant;

// 定义 ProjectMapper 的数据库访问操作。
public interface ProjectMapper {
    // 向数据库写入 insert 对应的记录。
    int insert(Project project);
    // 从数据库查询 findById 对应的记录。
    Project findById(@Param("id") UUID id);
    // 从数据库查询 findAllOrderByCreatedAtDesc 对应的记录。
    List<Project> findAllOrderByCreatedAtDesc();
    // 从数据库查询 findAllIncludingArchivedOrderByCreatedAtDesc 对应的记录。
    List<Project> findAllIncludingArchivedOrderByCreatedAtDesc();
    // 更新数据库中 updateDetails 对应的记录。
    int updateDetails(@Param("id") UUID id, @Param("name") String name,
                      @Param("description") String description, @Param("updatedAt") Instant updatedAt);
    // 执行 setArchivedAt 对应的数据库访问操作。
    int setArchivedAt(@Param("id") UUID id, @Param("archivedAt") Instant archivedAt,
                      @Param("updatedAt") Instant updatedAt);
}
