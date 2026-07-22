package com.deepaudit.domain;

import java.time.Instant;
import java.util.UUID;

public class Project {

    private UUID id;
    private String name;
    private String originalFilename;
    private String storagePath;
    private Instant createdAt;

    public Project() {
    }

    public Project(String name, String originalFilename, String storagePath) {
        this(UUID.randomUUID(), name, originalFilename, storagePath);
    }

    public Project(UUID id, String name, String originalFilename, String storagePath) {
        this.id = id;
        this.name = name;
        this.originalFilename = originalFilename;
        this.storagePath = storagePath;
        this.createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public String getName() { return name; }
    public String getOriginalFilename() { return originalFilename; }
    public String getStoragePath() { return storagePath; }
    public Instant getCreatedAt() { return createdAt; }
    public void setId(UUID id) { this.id = id; }
    public void setName(String name) { this.name = name; }
    public void setOriginalFilename(String originalFilename) { this.originalFilename = originalFilename; }
    public void setStoragePath(String storagePath) { this.storagePath = storagePath; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
