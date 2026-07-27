package com.deepaudit.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
public class AiReportSummary {
    private UUID taskId; // 报告摘要所属的审计任务 ID
    private String executiveSummary; // 面向决策者的审计结论摘要
    private String coverageSummary; // 本次审计范围与覆盖情况摘要
    private Instant generatedAt; // 摘要生成时间

    public AiReportSummary(UUID taskId, String executiveSummary, String coverageSummary) {
        this.taskId = taskId;
        this.executiveSummary = executiveSummary;
        this.coverageSummary = coverageSummary;
        this.generatedAt = Instant.now();
    }

}
