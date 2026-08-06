package com.deepaudit.report;

import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.AuditTask;
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
        AuditTask task = new AuditTask(projectId, "base-commit", "target-commit", "base-commit");
        task.setId(taskId);
        Project project = new Project(projectId, "示例项目", "data/example",
                "https://example.test/repository.git", "main");
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "demo/UserService.java", 73, 73, null,
                "外部输入直接进入动态 SQL。[CHUNK 999] 代码块 123 是内部定位信息。",
                "[CHUNK 1] [漏洞位置] demo/UserService.java:73 UserService#search\n"
                        + ">>>    73 | return statement.executeQuery(sql);\n\n"
                        + "[CHUNK 2] [调用入口] demo/UserController.java:31 UserController#search\n"
                        + "   31 | return service.search(name);\n\n"
                        + "[CHUNK 3] [关联证据] demo/Legacy.java:80 Legacy#run",
                "使用参数化查询");
        when(taskMapper.findById(taskId)).thenReturn(task);
        when(projectMapper.findById(projectId)).thenReturn(project);
        when(findingMapper.findByTaskIdOrderByRisk(taskId)).thenReturn(List.of(finding));
        ReportService service = new ReportService(taskMapper, projectMapper, findingMapper,
                mock(AgentRunMapper.class), mock(AuditHypothesisMapper.class), mock(AiReportSummaryMapper.class),
                mock(GitFileChangeMapper.class));

        String html = service.html(taskId);

        assertThat(html).contains("漏洞说明", "外部输入直接进入动态 SQL。")
                .contains("evidence-code-line vulnerable", "evidence-line-number'>73")
                .doesNotContain("代码证据", "Critic Agent 复核", ">CHUNK 1<", ">CHUNK 2<",
                        "&gt;&gt;&gt;", "#a22818", "#6b2429", "CHUNK 999", "代码块 123");
        assertThat(html).doesNotContain("Legacy.java", "Legacy#run");
    }

    private Finding finding(UUID taskId, FindingDeltaStatus status) {
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION,
                Severity.HIGH, Confidence.HIGH, "测试问题", "demo/Test.java", 1, 1,
                null, "测试描述", "[漏洞位置]", "测试修复建议");
        finding.setDeltaStatus(status);
        return finding;
    }
}
