package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class Project {

    private UUID id; // 项目的唯一标识
    private String name; // 用户可识别的项目名称
    private String originalFilename; // ZIP 来源项目的原始上传文件名
    private String storagePath; // 项目归档或裸 Git 仓库的服务端存储路径
    private ProjectSourceType sourceType; // 项目来源类型：Git 仓库或 ZIP 包
    private String repositoryUrl; // Git 来源项目的远程仓库地址
    private String defaultBranch; // Git 仓库用于默认扫描的分支名
    private String description; // 项目的补充说明
    private Instant createdAt; // 项目创建时间
    private Instant updatedAt; // 项目信息最后更新时间
    private Instant archivedAt; // 项目归档时间，未归档时为空

    public Project(String name, String originalFilename, String storagePath) {
        this(UUID.randomUUID(), name, originalFilename, storagePath);
    }

    public Project(UUID id, String name, String originalFilename, String storagePath) {
        this(id, name, originalFilename, storagePath, ProjectSourceType.ZIP, null, null);
    }

    public Project(UUID id, String name, String originalFilename, String storagePath,
                   ProjectSourceType sourceType, String repositoryUrl, String defaultBranch) {
        this.id = id;
        this.name = name;
        this.originalFilename = originalFilename;
        this.storagePath = storagePath;
        this.sourceType = sourceType;
        this.repositoryUrl = repositoryUrl;
        this.defaultBranch = defaultBranch;
        this.description = "";
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    public boolean isArchived() {
        return archivedAt != null;
    }

}
