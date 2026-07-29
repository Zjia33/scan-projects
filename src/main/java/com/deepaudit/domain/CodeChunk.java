package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class CodeChunk {

    private Long id; // 代码块的数据库自增主键
    private UUID taskId; // 代码块所属的审计任务 ID
    private String filePath; // 代码块在项目快照中的相对文件路径
    private String symbolName; // 代码块对应的方法、类型或配置符号名
    private String endpoint; // 代码块关联的 HTTP 接口信息
    private int startLine; // 代码块在文件中的起始行号
    private int endLine; // 代码块在文件中的结束行号
    private String content; // 目标快照中的代码块原文
    private String chunkType; // 代码块类型，如方法、配置或普通文本
    private String parameters; // 符号参数信息的序列化文本
    private String annotations; // 符号注解信息的序列化文本
    private String calledSymbols; // 代码块直接调用的符号集合序列化文本
    private ChunkChangeType changeType; // 相对基线快照的代码块变更类型
    private AnalysisScope analysisScope; // 增量审计中该代码块承担的分析范围角色
    private String baseContent; // 增量扫描中与当前代码块对应的基线内容

    public CodeChunk(UUID taskId, String filePath, String symbolName, String endpoint,
                     int startLine, int endLine, String content) {
        this(taskId, filePath, symbolName, endpoint, startLine, endLine, content,
                "TEXT", "", "", "");
    }

    public CodeChunk(UUID taskId, String filePath, String symbolName, String endpoint,
                     int startLine, int endLine, String content,
                     String chunkType, String parameters, String annotations, String calledSymbols) {
        this.taskId = taskId;
        this.filePath = filePath;
        this.symbolName = symbolName;
        this.endpoint = endpoint;
        this.startLine = startLine;
        this.endLine = endLine;
        this.content = content;
        this.chunkType = chunkType;
        this.parameters = parameters;
        this.annotations = annotations;
        this.calledSymbols = calledSymbols;
        this.changeType = ChunkChangeType.UNCHANGED;
        this.analysisScope = AnalysisScope.FULL;
        this.baseContent = "";
    }

}
