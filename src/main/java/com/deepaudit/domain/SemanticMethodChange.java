package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class SemanticMethodChange {
    private UUID id; // 方法级语义变更记录的唯一标识
    private UUID taskId; // 变更记录所属的增量审计任务 ID
    private SemanticChangeKind changeKind; // 方法新增、修改、删除或 Guard 变化等类型
    private String methodName; // 发生语义变化的方法名称
    private String basePath; // 方法在基线提交中的相对文件路径
    private String targetPath; // 方法在目标提交中的相对文件路径
    private String baseSymbol; // 基线方法的规范化符号标识
    private String targetSymbol; // 目标方法的规范化符号标识
    private Integer baseStartLine; // 基线方法的起始行号，不存在时为空
    private Integer baseEndLine; // 基线方法的结束行号，不存在时为空
    private Integer targetStartLine; // 目标方法的起始行号，不存在时为空
    private Integer targetEndLine; // 目标方法的结束行号，不存在时为空
    private String baseContent; // 基线方法快照内容
    private String targetContent; // 目标方法快照内容
    private String details; // 签名或 Guard 等语义差异的可读说明

    public SemanticMethodChange(UUID taskId, SemanticChangeKind changeKind, String methodName,
                                String basePath, String targetPath, String baseSymbol,
                                String targetSymbol, Integer baseStartLine, Integer baseEndLine,
                                Integer targetStartLine, Integer targetEndLine, String baseContent,
                                String targetContent, String details) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.changeKind = changeKind;
        this.methodName = safe(methodName);
        this.basePath = basePath;
        this.targetPath = targetPath;
        this.baseSymbol = baseSymbol;
        this.targetSymbol = targetSymbol;
        this.baseStartLine = baseStartLine;
        this.baseEndLine = baseEndLine;
        this.targetStartLine = targetStartLine;
        this.targetEndLine = targetEndLine;
        this.baseContent = safe(baseContent);
        this.targetContent = safe(targetContent);
        this.details = safe(details);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }
}
