package com.deepaudit.domain;

import java.util.UUID;

// 程序中的一个可分析节点，例如Java方法，Mybatis SQL，框架数据库调用..
public class SemanticSymbol {
    private UUID id;
    private UUID taskId;
    private Long chunkId;
    private String kind;
    private String qualifiedName;
    private String simpleName;
    private String ownerName;
    private String signature;
    private String returnType;
    private String parameterTypes;
    private String filePath;
    private int startLine;
    private int endLine;
    private String endpoint;
    private String annotations;
    private String details;

    public SemanticSymbol() {}

    public SemanticSymbol(UUID taskId, Long chunkId, String kind, String qualifiedName, String simpleName,
                          String ownerName, String signature, String returnType, String parameterTypes,
                          String filePath, int startLine, int endLine, String endpoint,
                          String annotations, String details) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.chunkId = chunkId;
        this.kind = kind;
        this.qualifiedName = qualifiedName;
        this.simpleName = simpleName;
        this.ownerName = ownerName;
        this.signature = signature;
        this.returnType = returnType;
        this.parameterTypes = parameterTypes == null ? "" : parameterTypes;
        this.filePath = filePath;
        this.startLine = startLine;
        this.endLine = endLine;
        this.endpoint = endpoint;
        this.annotations = annotations == null ? "" : annotations;
        this.details = details == null ? "" : details;
    }

    public UUID getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public Long getChunkId() { return chunkId; }
    public String getKind() { return kind; }
    public String getQualifiedName() { return qualifiedName; }
    public String getSimpleName() { return simpleName; }
    public String getOwnerName() { return ownerName; }
    public String getSignature() { return signature; }
    public String getReturnType() { return returnType; }
    public String getParameterTypes() { return parameterTypes; }
    public String getFilePath() { return filePath; }
    public int getStartLine() { return startLine; }
    public int getEndLine() { return endLine; }
    public String getEndpoint() { return endpoint; }
    public String getAnnotations() { return annotations; }
    public String getDetails() { return details; }
    public void setId(UUID id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setChunkId(Long chunkId) { this.chunkId = chunkId; }
    public void setKind(String kind) { this.kind = kind; }
    public void setQualifiedName(String qualifiedName) { this.qualifiedName = qualifiedName; }
    public void setSimpleName(String simpleName) { this.simpleName = simpleName; }
    public void setOwnerName(String ownerName) { this.ownerName = ownerName; }
    public void setSignature(String signature) { this.signature = signature; }
    public void setReturnType(String returnType) { this.returnType = returnType; }
    public void setParameterTypes(String parameterTypes) { this.parameterTypes = parameterTypes; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public void setStartLine(int startLine) { this.startLine = startLine; }
    public void setEndLine(int endLine) { this.endLine = endLine; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    public void setAnnotations(String annotations) { this.annotations = annotations; }
    public void setDetails(String details) { this.details = details; }
}
