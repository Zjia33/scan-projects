package com.deepaudit.domain;

import java.util.UUID;

public class CodeChunk {

    private Long id;
    private UUID taskId;
    private String filePath;
    private String symbolName;
    private String endpoint;
    private int startLine;
    private int endLine;
    private String content;
    private String embedding;
    private String chunkType;
    private String parameters;
    private String annotations;
    private String calledSymbols;

    public CodeChunk() {
    }

    public CodeChunk(UUID taskId, String filePath, String symbolName, String endpoint,
                     int startLine, int endLine, String content, String embedding) {
        this(taskId, filePath, symbolName, endpoint, startLine, endLine, content, embedding,
                "TEXT", "", "", "");
    }

    public CodeChunk(UUID taskId, String filePath, String symbolName, String endpoint,
                     int startLine, int endLine, String content, String embedding,
                     String chunkType, String parameters, String annotations, String calledSymbols) {
        this.taskId = taskId;
        this.filePath = filePath;
        this.symbolName = symbolName;
        this.endpoint = endpoint;
        this.startLine = startLine;
        this.endLine = endLine;
        this.content = content;
        this.embedding = embedding;
        this.chunkType = chunkType;
        this.parameters = parameters;
        this.annotations = annotations;
        this.calledSymbols = calledSymbols;
    }

    public Long getId() { return id; }
    public UUID getTaskId() { return taskId; }
    public String getFilePath() { return filePath; }
    public String getSymbolName() { return symbolName; }
    public String getEndpoint() { return endpoint; }
    public int getStartLine() { return startLine; }
    public int getEndLine() { return endLine; }
    public String getContent() { return content; }
    public String getEmbedding() { return embedding; }
    public String getChunkType() { return chunkType; }
    public String getParameters() { return parameters; }
    public String getAnnotations() { return annotations; }
    public String getCalledSymbols() { return calledSymbols; }
    public void setId(Long id) { this.id = id; }
    public void setTaskId(UUID taskId) { this.taskId = taskId; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public void setSymbolName(String symbolName) { this.symbolName = symbolName; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    public void setStartLine(int startLine) { this.startLine = startLine; }
    public void setEndLine(int endLine) { this.endLine = endLine; }
    public void setContent(String content) { this.content = content; }
    public void setEmbedding(String embedding) { this.embedding = embedding; }
    public void setChunkType(String chunkType) { this.chunkType = chunkType; }
    public void setParameters(String parameters) { this.parameters = parameters; }
    public void setAnnotations(String annotations) { this.annotations = annotations; }
    public void setCalledSymbols(String calledSymbols) { this.calledSymbols = calledSymbols; }
}
