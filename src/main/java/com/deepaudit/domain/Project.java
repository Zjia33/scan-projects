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

    private UUID id;
    private String name;
    private String originalFilename;
    private String storagePath;
    private ProjectSourceType sourceType;
    private String repositoryUrl;
    private String defaultBranch;
    private Instant createdAt;

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
        this.createdAt = Instant.now();
    }

}
