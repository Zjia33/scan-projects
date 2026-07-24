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
    private UUID taskId;
    private String executiveSummary;
    private String coverageSummary;
    private Instant generatedAt;

    public AiReportSummary(UUID taskId, String executiveSummary, String coverageSummary) {
        this.taskId = taskId;
        this.executiveSummary = executiveSummary;
        this.coverageSummary = coverageSummary;
        this.generatedAt = Instant.now();
    }

}
