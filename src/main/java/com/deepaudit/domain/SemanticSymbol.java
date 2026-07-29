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
    private UUID id; // 语义符号的唯一标识
    private UUID taskId; // 符号所属的审计任务 ID
    private Long chunkId; // 符号对应的代码块 ID，无对应块时为空
    private String kind; // 符号种类，如 Java 方法或 MyBatis SQL
    private String qualifiedName; // 包含所有者信息的符号限定名
    private String simpleName; // 不含所有者信息的简单符号名
    private String ownerName; // 声明该符号的类、接口或命名空间
    private String signature; // 用于重载区分与匹配的完整签名
    private String returnType; // 方法或语句结果的返回类型
    private String parameterTypes; // 参数类型列表的序列化文本
    private String filePath; // 符号所在的项目相对文件路径
    private int startLine; // 符号定义的起始行号
    private int endLine; // 符号定义的结束行号
    private String endpoint; // 符号关联的 HTTP 接口信息
    private String annotations; // 符号声明上的注解序列化文本
    private String details; // 用于语义分析的源码及结构化摘要

    // 创建 SemanticSymbol 实例并初始化所需依赖或状态。
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
