package com.deepaudit.mapper;

import com.deepaudit.domain.Project;
import org.apache.ibatis.annotations.Param;

import java.util.UUID;
import java.util.List;
import java.time.Instant;

public interface ProjectMapper {
    int insert(Project project);
    Project findById(@Param("id") UUID id);
    List<Project> findAllOrderByCreatedAtDesc();
    List<Project> findAllIncludingArchivedOrderByCreatedAtDesc();
    int updateDetails(@Param("id") UUID id, @Param("name") String name,
                      @Param("description") String description, @Param("updatedAt") Instant updatedAt);
    int setArchivedAt(@Param("id") UUID id, @Param("archivedAt") Instant archivedAt,
                      @Param("updatedAt") Instant updatedAt);
}
