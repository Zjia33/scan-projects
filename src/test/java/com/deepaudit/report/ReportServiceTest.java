package com.deepaudit.report;

import com.deepaudit.domain.AiReportSummary;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.HypothesisStatus;
import com.deepaudit.domain.Project;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.AgentRunMapper;
import com.deepaudit.mapper.AiReportSummaryMapper;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.FindingMapper;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.ProjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReportServiceTest {

    @Test
    void preservesIncrementalDeltaStatusesForFinalReport() {
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        FindingMapper findingMapper = mock(FindingMapper.class);
        AuditTask task = new AuditTask(UUID.randomUUID(), "base", "target", "base");
        task.setId(taskId);
        Finding changed = finding(taskId, FindingDeltaStatus.NEW);
        Finding persisting = finding(taskId, FindingDeltaStatus.PERSISTING);
        when(taskMapper.findById(taskId)).thenReturn(task);
        when(findingMapper.findByTaskIdOrderByRisk(taskId))
                .thenReturn(List.of(changed, persisting));
        ReportService service = new ReportService(taskMapper, mock(ProjectMapper.class),
                findingMapper, mock(AgentRunMapper.class), mock(AuditHypothesisMapper.class),
                mock(AiReportSummaryMapper.class), mock(GitFileChangeMapper.class));

        List<FindingDeltaStatus> statuses = service.findings(taskId).stream()
                .map(Finding::getDeltaStatus).toList();

        assertThat(statuses).containsExactly(FindingDeltaStatus.NEW, FindingDeltaStatus.PERSISTING);
    }

    @Test
    void rendersOneDescriptionAndSeparatesEvidenceChunksWithoutRedLineHighlight() {
        UUID projectId = UUID.randomUUID();
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        ProjectMapper projectMapper = mock(ProjectMapper.class);
        FindingMapper findingMapper = mock(FindingMapper.class);
        AiReportSummaryMapper summaryMapper = mock(AiReportSummaryMapper.class);
        AuditTask task = new AuditTask(projectId, "base-commit", "target-commit", "base-commit");
        task.setId(taskId);
        Project project = new Project(projectId, "示例项目", "data/example",
                "https://example.test/repository.git", "main");
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入（chunk 165）", "demo/UserService.java", 73, 73, null,
                "外部输入直接进入动态 SQL（chunk 165）。代码删除了输出编码（chunk 155 第61-62行）。"
                        + "\n\nCritic Agent 复核：外部输入直接进入动态 SQL（CHUNK_ID=165）。",
                "[CHUNK 1] [漏洞根因] demo/UserService.java:73 UserService#search\n"
                        + ">>>    73 | return statement.executeQuery(sql);\n\n"
                        + "[CHUNK 2] [调用入口] demo/UserController.java:31 UserController#search\n"
                        + "   31 | return service.search(name);",
                "使用参数化查询（primaryChunkId=165）");
        when(taskMapper.findById(taskId)).thenReturn(task);
        when(projectMapper.findById(projectId)).thenReturn(project);
        when(findingMapper.findByTaskIdOrderByRisk(taskId)).thenReturn(List.of(finding));
        when(summaryMapper.findByTaskId(taskId)).thenReturn(new AiReportSummary(taskId,
                "确认一个高危问题（chunk 165）。主要风险来自动态 SQL（CHUNK_ID=155）。"));
        ReportService service = new ReportService(taskMapper, projectMapper, findingMapper,
                mock(AgentRunMapper.class), mock(AuditHypothesisMapper.class), summaryMapper,
                mock(GitFileChangeMapper.class));

        String html = service.html(taskId);

        assertThat(html).contains("动态 SQL 注入", "漏洞说明", "外部输入直接进入动态 SQL。",
                        "代码删除了输出编码。", "审计摘要", "确认一个高危问题。",
                        "主要风险来自动态 SQL。", "代码证据", "实际漏洞位置", "使用参数化查询")
                .contains("evidence-code-line vulnerable", "evidence-line-number'>73")
                .doesNotContain("代码证据 1", "代码证据 2", "Critic Agent 复核", ">CHUNK 1<", ">CHUNK 2<",
                        "chunk 165", "chunk 155", "CHUNK_ID=165", "primaryChunkId=165",
                        "&gt;&gt;&gt;", "#a22818", "#6b2429", "审计覆盖", "coverage");
    }

    @Test
    void doesNotRenderHistoricalUnlocatedHypothesisAsVulnerability() {
        UUID projectId = UUID.randomUUID();
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        ProjectMapper projectMapper = mock(ProjectMapper.class);
        FindingMapper findingMapper = mock(FindingMapper.class);
        AgentRunMapper agentRunMapper = mock(AgentRunMapper.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        GitFileChangeMapper changeMapper = mock(GitFileChangeMapper.class);
        AuditTask task = new AuditTask(projectId, "base-commit", "target-commit", "base-commit");
        task.setId(taskId);
        Project project = new Project(projectId, "示例项目", "data/example",
                "https://example.test/repository.git", "main");
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.VALIDATION_BYPASS, "未验证指令可以执行", 2100L,
                "2100", Confidence.HIGH);
        hypothesis.setStatus(HypothesisStatus.CONFIRMED_UNLOCATED);
        hypothesis.setCriticReason("Critic 已确认漏洞，但精确位置仍待复核");
        when(taskMapper.findById(taskId)).thenReturn(task);
        when(projectMapper.findById(projectId)).thenReturn(project);
        when(findingMapper.findByTaskIdOrderByRisk(taskId)).thenReturn(List.of());
        when(agentRunMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(hypothesisMapper.findByTaskId(taskId)).thenReturn(List.of(hypothesis));
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of());
        ReportService service = new ReportService(taskMapper, projectMapper, findingMapper,
                agentRunMapper, hypothesisMapper, mock(AiReportSummaryMapper.class), changeMapper);

        String html = service.html(taskId);

        assertThat(html).contains("本轮审计没有产生已完成精确定位的问题")
                .doesNotContain("已确认但定位待复核", "未验证指令可以执行",
                        "报告不标红任意代码行", "定位待复核");
    }

    private Finding finding(UUID taskId, FindingDeltaStatus status) {
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION,
                Severity.HIGH, Confidence.HIGH, "测试问题", "demo/Test.java", 1, 1,
                null, "测试描述", "[漏洞根因]", "测试修复建议");
        finding.setDeltaStatus(status);
        return finding;
    }
}
