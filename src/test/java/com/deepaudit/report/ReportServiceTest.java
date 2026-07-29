package com.deepaudit.report;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.AuditTask;
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

    private Finding finding(UUID taskId, FindingDeltaStatus status) {
        Finding finding = new Finding(taskId, VulnerabilityType.SQL_INJECTION,
                Severity.HIGH, Confidence.HIGH, "测试问题", "demo/Test.java", 1, 1,
                null, "测试描述", "[漏洞位置]", "测试修复建议");
        finding.setDeltaStatus(status);
        return finding;
    }
}
