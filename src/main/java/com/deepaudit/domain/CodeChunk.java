package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
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
    private ChunkChangeType changeType;
    private AnalysisScope analysisScope;
    private String baseContent;

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
        this.changeType = ChunkChangeType.UNCHANGED;
        this.analysisScope = AnalysisScope.FULL;
        this.baseContent = "";
    }

}
