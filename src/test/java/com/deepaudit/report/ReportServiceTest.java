package com.deepaudit.report;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.domain.HypothesisStatus;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Project;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.AgentRunMapper;
import com.deepaudit.mapper.AiReportSummaryMapper;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.CodeChunkMapper;
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
    void normalizesLegacyIncrementalDeltaStatusesForFinalReport() {
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        FindingMapper findingMapper = mock(FindingMapper.class);
        CodeChunkMapper chunkMapper = mock(CodeChunkMapper.class);
        AuditTask task = new AuditTask(UUID.randomUUID(), ScanMode.INCREMENTAL,
                "base", "target", "base");
        task.setId(taskId);
        Finding baseline = finding(taskId, FindingDeltaStatus.BASELINE);
        Finding regressed = finding(taskId, FindingDeltaStatus.REGRESSED);
        Finding affected = finding(taskId, FindingDeltaStatus.AFFECTED);
        Finding persisting = finding(taskId, FindingDeltaStatus.PERSISTING);
        when(taskMapper.findById(taskId)).thenReturn(task);
        when(findingMapper.findByTaskIdOrderByRisk(taskId))
                .thenReturn(List.of(baseline, regressed, affected, persisting));
        when(chunkMapper.findByTaskId(taskId)).thenReturn(List.of());
        ReportService service = new ReportService(taskMapper, mock(ProjectMapper.class),
                findingMapper, mock(AgentRunMapper.class), mock(AuditHypothesisMapper.class),
                mock(AiReportSummaryMapper.class), mock(GitFileChangeMapper.class), chunkMapper);

        List<FindingDeltaStatus> statuses = service.findings(taskId).stream()
                .map(Finding::getDeltaStatus).toList();

        assertThat(statuses).containsExactly(FindingDeltaStatus.NEW, FindingDeltaStatus.NEW,
                FindingDeltaStatus.NEW, FindingDeltaStatus.PERSISTING);
    }

    @Test
    void convertsLegacyWholeMethodEvidenceToMarkedLocalContext() {
        UUID taskId = UUID.randomUUID();
        FindingMapper findingMapper = mock(FindingMapper.class);
        CodeChunkMapper chunkMapper = mock(CodeChunkMapper.class);
        String method = """
                public List<User> search(String name) {
                    String sql = "select * from users where name='" + name + "'";
                    audit(name);
                    return statement.executeQuery(sql);
                    cleanup();
                    return List.of();
                }
                """;
        CodeChunk chunk = new CodeChunk(taskId, "demo/UserService.java", "UserService#search", null,
                70, 76, method, "JAVA_METHOD", "String name", "", "executeQuery");
        chunk.setId(1L);
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", chunk.getFilePath(), 70, 76, null, "外部输入进入 executeQuery",
                "[CHUNK 1] demo/UserService.java:70 UserService#search\n" + method,
                "使用参数化查询");
        when(findingMapper.findByTaskIdOrderByRisk(taskId)).thenReturn(List.of(finding));
        when(chunkMapper.findByTaskId(taskId)).thenReturn(List.of(chunk));
        ReportService service = new ReportService(mock(AuditTaskMapper.class), mock(ProjectMapper.class),
                findingMapper, mock(AgentRunMapper.class), mock(AuditHypothesisMapper.class),
                mock(AiReportSummaryMapper.class), mock(GitFileChangeMapper.class), chunkMapper);

        Finding displayed = service.findings(taskId).get(0);

        assertThat(displayed.getStartLine()).isEqualTo(73);
        assertThat(displayed.getEndLine()).isEqualTo(73);
        assertThat(displayed.getEvidence()).contains("[漏洞位置]", ">>>    73 |")
                .doesNotContain("demo/UserService.java:70 UserService#search\npublic");
    }

    @Test
    void rendersOneDescriptionAndSeparatesEvidenceChunksWithoutRedLineHighlight() {
        UUID projectId = UUID.randomUUID();
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        ProjectMapper projectMapper = mock(ProjectMapper.class);
        FindingMapper findingMapper = mock(FindingMapper.class);
        CodeChunkMapper chunkMapper = mock(CodeChunkMapper.class);
        AuditTask task = new AuditTask(projectId, ScanMode.FULL, null, "target-commit", null);
        task.setId(taskId);
        Project project = new Project(projectId, "示例项目", null, "data/example");
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "demo/UserService.java", 73, 73, null,
                "外部输入直接进入动态 SQL。\n\nCritic Agent 复核：外部输入直接进入动态 SQL。",
                "[CHUNK 1] [漏洞位置] demo/UserService.java:73 UserService#search\n"
                        + ">>>    73 | return statement.executeQuery(sql);\n\n"
                        + "[CHUNK 2] [调用入口] demo/UserController.java:31 UserController#search\n"
                        + "   31 | return service.search(name);",
                "使用参数化查询");
        when(taskMapper.findById(taskId)).thenReturn(task);
        when(projectMapper.findById(projectId)).thenReturn(project);
        when(findingMapper.findByTaskIdOrderByRisk(taskId)).thenReturn(List.of(finding));
        when(chunkMapper.findByTaskId(taskId)).thenReturn(List.of());
        ReportService service = new ReportService(taskMapper, projectMapper, findingMapper,
                mock(AgentRunMapper.class), mock(AuditHypothesisMapper.class), mock(AiReportSummaryMapper.class),
                mock(GitFileChangeMapper.class), chunkMapper);

        String html = service.html(taskId);

        assertThat(html).contains("漏洞说明", "外部输入直接进入动态 SQL。", "CHUNK 1", "CHUNK 2")
                .contains("evidence-code-line vulnerable", "evidence-line-number'>73")
                .doesNotContain("Critic Agent 复核", "&gt;&gt;&gt;", "#a22818", "#6b2429");
    }

    @Test
    void rendersConfirmedButUnlocatedHypothesisWithoutInventingRedLine() {
        UUID projectId = UUID.randomUUID();
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        ProjectMapper projectMapper = mock(ProjectMapper.class);
        FindingMapper findingMapper = mock(FindingMapper.class);
        CodeChunkMapper chunkMapper = mock(CodeChunkMapper.class);
        AgentRunMapper agentRunMapper = mock(AgentRunMapper.class);
        AuditHypothesisMapper hypothesisMapper = mock(AuditHypothesisMapper.class);
        GitFileChangeMapper changeMapper = mock(GitFileChangeMapper.class);
        AuditTask task = new AuditTask(projectId, ScanMode.FULL, null, "target-commit", null);
        task.setId(taskId);
        Project project = new Project(projectId, "示例项目", null, "data/example");
        AuditHypothesis hypothesis = new AuditHypothesis(taskId, UUID.randomUUID(),
                VulnerabilityType.FINANCIAL_RISK, "未验证资金指令可以执行", 2100L,
                "2100", Confidence.HIGH);
        hypothesis.setStatus(HypothesisStatus.CONFIRMED_UNLOCATED);
        hypothesis.setCriticReason("Critic 已确认漏洞，但精确位置仍待复核");
        when(taskMapper.findById(taskId)).thenReturn(task);
        when(projectMapper.findById(projectId)).thenReturn(project);
        when(findingMapper.findByTaskIdOrderByRisk(taskId)).thenReturn(List.of());
        when(chunkMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(agentRunMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(hypothesisMapper.findByTaskId(taskId)).thenReturn(List.of(hypothesis));
        when(changeMapper.findByTaskId(taskId)).thenReturn(List.of());
        ReportService service = new ReportService(taskMapper, projectMapper, findingMapper,
                agentRunMapper, hypothesisMapper, mock(AiReportSummaryMapper.class), changeMapper, chunkMapper);

        String html = service.html(taskId);

        assertThat(html).contains("已确认但定位待复核", "未验证资金指令可以执行",
                        "报告不标红任意代码行", "定位待复核</small><strong>1")
                .doesNotContain("实际漏洞位置</b><span>2100");
    }

    private Finding finding(UUID taskId, FindingDeltaStatus status) {
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION,
                Severity.HIGH, Confidence.HIGH, "测试问题", "demo/Test.java", 1, 1,
                null, "测试描述", "[漏洞位置]", "测试修复建议");
        finding.setDeltaStatus(status);
        return finding;
    }
}
