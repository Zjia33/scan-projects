package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

// 程序中的一个可分析节点，例如Java方法，Mybatis SQL，框架数据库调用..
@Getter
@Setter
@NoArgsConstructor
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

}
