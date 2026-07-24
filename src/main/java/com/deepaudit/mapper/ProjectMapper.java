package com.deepaudit.mapper;

import com.deepaudit.domain.Project;
import org.apache.ibatis.annotations.Param;

import java.util.UUID;
import java.util.List;

public interface ProjectMapper {
    int insert(Project project);
    Project findById(@Param("id") UUID id);
    List<Project> findAllOrderByCreatedAtDesc();
}
