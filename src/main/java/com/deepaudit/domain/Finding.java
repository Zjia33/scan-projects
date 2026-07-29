package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

// 表示审计领域中的 Finding 数据实体。
@Getter
@Setter
@NoArgsConstructor
public class Finding {

    private UUID id; // 已确认漏洞发现的唯一标识
    private UUID taskId; // 发现所属的审计任务 ID
    private VulnerabilityType type; // 漏洞类型
    private Severity severity; // 漏洞影响严重程度
    private Confidence confidence; // 证据支持该发现的置信度
    private String title; // 漏洞发现标题
    private String filePath; // 主证据所在的项目相对文件路径
    private int startLine; // 主证据的起始行号
    private int endLine; // 主证据的结束行号
    private String endpoint; // 漏洞影响的 HTTP 接口信息
    private String description; // 漏洞成因、触发条件与影响说明
    private String evidence; // 经验证的代码证据及调用链说明
    private String remediation; // 针对该漏洞的修复建议
    private FindingDeltaStatus deltaStatus; // 发现相对基线任务的增量状态
    private String fingerprint; // 用于跨扫描匹配和去重的稳定指纹
    private Instant createdAt; // 发现记录创建时间

    // 创建 Finding 实例并初始化所需依赖或状态。
    public Finding(UUID taskId, VulnerabilityType type, Severity severity, Confidence confidence,
                   String title, String filePath, int startLine, int endLine, String endpoint,
                   String description, String evidence, String remediation) {
        this.id = UUID.randomUUID();
        this.taskId = taskId;
        this.type = type;
        this.severity = severity;
        this.confidence = confidence;
        this.title = title;
        this.filePath = filePath;
        this.startLine = startLine;
        this.endLine = endLine;
        this.endpoint = endpoint;
        this.description = description;
        this.evidence = evidence;
        this.remediation = remediation;
        this.deltaStatus = FindingDeltaStatus.BASELINE;
        this.createdAt = Instant.now();
    }

}
