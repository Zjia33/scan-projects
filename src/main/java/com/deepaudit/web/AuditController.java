package com.deepaudit.web;

import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.Project;
import com.deepaudit.domain.AgentEvent;
import com.deepaudit.domain.AgentRun;
import com.deepaudit.domain.AuditHypothesis;
import com.deepaudit.report.ReportService;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.FindingMapper;
import com.deepaudit.mapper.ProjectMapper;
import com.deepaudit.mapper.AgentEventMapper;
import com.deepaudit.mapper.AgentRunMapper;
import com.deepaudit.mapper.AuditHypothesisMapper;
import com.deepaudit.service.ProjectService;
import com.deepaudit.agent.AgentEventStreamService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class AuditController {

    private final ProjectService projectService;
    private final ProjectMapper projectMapper;
    private final AuditTaskMapper taskMapper;
    private final FindingMapper findingMapper;
    private final ReportService reportService;
    private final AgentRunMapper agentRunMapper;
    private final AgentEventMapper agentEventMapper;
    private final AuditHypothesisMapper hypothesisMapper;
    private final AgentEventStreamService eventStreamService;

    public AuditController(ProjectService projectService,
                           ProjectMapper projectMapper,
                           AuditTaskMapper taskMapper,
                           FindingMapper findingMapper,
                           ReportService reportService,
                           AgentRunMapper agentRunMapper,
                           AgentEventMapper agentEventMapper,
                           AuditHypothesisMapper hypothesisMapper,
                           AgentEventStreamService eventStreamService) {
        this.projectService = projectService;
        this.projectMapper = projectMapper;
        this.taskMapper = taskMapper;
        this.findingMapper = findingMapper;
        this.reportService = reportService;
        this.agentRunMapper = agentRunMapper;
        this.agentEventMapper = agentEventMapper;
        this.hypothesisMapper = hypothesisMapper;
        this.eventStreamService = eventStreamService;
    }

    // 接收项目 ZIP 并返回已进入后台扫描队列的任务信息。
    @PostMapping(value = "/projects/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<UploadResponse> upload(@RequestParam(required = false) String name,
                                                 @RequestParam("file") MultipartFile file) throws IOException {
        ProjectService.Submission submission = projectService.submit(name, file);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new UploadResponse(
                submission.project().getId(), submission.task().getId(), submission.project().getName(),
                "ZIP 已接收，扫描任务正在后台执行"));
    }

    // 返回任务列表及控制台展示所需的 Agent 调用统计。
    @GetMapping("/tasks")
    public List<TaskResponse> tasks() {
        return taskMapper.findAllOrderByCreatedAtDesc().stream().map(this::toResponse).toList();
    }

    // 查询单个任务的最新阶段、进度和统计信息。
    @GetMapping("/tasks/{taskId}")
    public TaskResponse task(@PathVariable UUID taskId) {
        AuditTask task = taskMapper.findById(taskId);
        if (task == null) throw new java.util.NoSuchElementException("扫描任务不存在: " + taskId);
        return toResponse(task);
    }

    // 仅返回经过证据过滤后可展示的最终漏洞列表。
    @GetMapping("/tasks/{taskId}/findings")
    public List<Finding> findings(@PathVariable UUID taskId) {
        if (taskMapper.findById(taskId) == null) {
            throw new java.util.NoSuchElementException("扫描任务不存在: " + taskId);
        }
        return reportService.findings(taskId);
    }

    // 返回任务下各类 Agent 的运行记录。
    @GetMapping("/tasks/{taskId}/agents")
    public List<AgentRun> agents(@PathVariable UUID taskId) {
        requireTask(taskId);
        return agentRunMapper.findByTaskId(taskId);
    }

    // 返回可供控制台回放的 Agent 事件历史。
    @GetMapping("/tasks/{taskId}/events")
    public List<AgentEvent> events(@PathVariable UUID taskId) {
        requireTask(taskId);
        return agentEventMapper.findByTaskId(taskId);
    }

    // 建立 SSE 订阅以实时推送扫描阶段和 Agent 事件。
    @GetMapping(value = "/tasks/{taskId}/events/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter eventStream(@PathVariable UUID taskId) {
        requireTask(taskId);
        return eventStreamService.subscribe(taskId);
    }

    // 返回专业 Agent 提交且由 Critic 处理过的调查假设。
    @GetMapping("/tasks/{taskId}/hypotheses")
    public List<AuditHypothesis> hypotheses(@PathVariable UUID taskId) {
        requireTask(taskId);
        return hypothesisMapper.findByTaskId(taskId);
    }

    // 聚合项目、任务、发现和 Agent 轨迹为结构化报告。
    @GetMapping("/tasks/{taskId}/report.json")
    public ReportService.AuditReport jsonReport(@PathVariable UUID taskId) {
        return reportService.report(taskId);
    }

    // 将同一份审计结果渲染成可直接浏览的 UTF-8 HTML 报告。
    @GetMapping(value = "/tasks/{taskId}/report.html", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<byte[]> htmlReport(@PathVariable UUID taskId) {
        byte[] report = reportService.html(taskId).getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=deepaudit-report.html")
                .contentType(new MediaType("text", "html", StandardCharsets.UTF_8))
                .body(report);
    }

    // 汇总任务实体与关联 Agent 计数，转换为控制台响应模型。
    private TaskResponse toResponse(AuditTask task) {
        Project project = projectMapper.findById(task.getProjectId());
        if (project == null) throw new java.util.NoSuchElementException("项目不存在: " + task.getProjectId());
        List<AgentRun> runs = agentRunMapper.findByTaskId(task.getId());
        int modelCalls = runs.stream().mapToInt(AgentRun::getModelCallCount).sum();
        int toolCalls = runs.stream().mapToInt(AgentRun::getToolCallCount).sum();
        return new TaskResponse(task.getId(), project.getId(), project.getName(), project.getOriginalFilename(),
                task.getStatus().name(), task.getProgress(), task.getCurrentStage(), task.getErrorMessage(),
                findingMapper.countByTaskId(task.getId()), runs.size(), modelCalls, toolCalls,
                task.getCreatedAt(), task.getCompletedAt());
    }

    // 统一校验需要任务上下文的查询接口。
    private AuditTask requireTask(UUID taskId) {
        AuditTask task = taskMapper.findById(taskId);
        if (task == null) throw new java.util.NoSuchElementException("扫描任务不存在: " + taskId);
        return task;
    }

    public record UploadResponse(UUID projectId, UUID taskId, String projectName, String message) {
    }

    public record TaskResponse(UUID taskId, UUID projectId, String projectName, String originalFilename,
                               String status, int progress, String currentStage, String errorMessage,
                               long findingCount, int agentRunCount, int modelCallCount, int toolCallCount,
                               java.time.Instant createdAt, java.time.Instant completedAt) {
    }
}
