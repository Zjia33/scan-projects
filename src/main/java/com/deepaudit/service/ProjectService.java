package com.deepaudit.service;

import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Project;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.git.GitRepositoryService;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.ProjectMapper;
import com.deepaudit.orchestrator.AuditOrchestrator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

// 负责 ProjectService 对应的业务编排和处理。
@Service
public class ProjectService {
    private final GitRepositoryService gitRepositoryService;
    private final ProjectMapper projectMapper;
    private final AuditTaskMapper taskMapper;
    private final AuditOrchestrator orchestrator;
    private final TransactionTemplate transactionTemplate;

    // 创建 ProjectService 实例并初始化所需依赖或状态。
    public ProjectService(GitRepositoryService gitRepositoryService,
                          ProjectMapper projectMapper,
                          AuditTaskMapper taskMapper,
                          AuditOrchestrator orchestrator,
                          PlatformTransactionManager transactionManager) {
        this.gitRepositoryService = gitRepositoryService;
        this.projectMapper = projectMapper;
        this.taskMapper = taskMapper;
        this.orchestrator = orchestrator;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    // 导入裸 Git 仓库并立即返回可选提交；访问令牌仅用于本次网络请求。
    public GitRepositoryService.ImportedRepository importRepository(String name, String repositoryUrl,
                                                                    String username, String accessToken)
            throws IOException {
        return gitRepositoryService.importRepository(name, repositoryUrl, username, accessToken);
    }

    // 执行 ProjectService 中的 projects 处理。
    public List<Project> projects() {
        return gitRepositoryService.projects();
    }

    // 执行 ProjectService 中的 projects 处理。
    public List<Project> projects(boolean includeArchived) {
        return gitRepositoryService.projects(includeArchived);
    }

    // 执行 ProjectService 中的 project 处理。
    public Project project(UUID projectId) {
        return requireProject(projectId);
    }

    // 只允许修改展示信息，仓库地址和本地裸仓库位置保持不可变。
    public Project updateProject(UUID projectId, String requestedName, String requestedDescription) {
        Project project = requireProject(projectId);
        String name = normalizeName(requestedName);
        String description = normalizeDescription(requestedDescription);
        Instant now = Instant.now();
        transactionTemplate.executeWithoutResult(status -> {
            if (projectMapper.updateDetails(projectId, name, description, now) != 1) {
                throw new IllegalStateException("更新项目信息失败");
            }
        });
        return requireProject(projectId);
    }

    // 归档会阻止刷新和新建扫描，但保留仓库、历史和报告数据。
    public Project archive(UUID projectId) {
        Project project = requireProject(projectId);
        if (project.isArchived()) return project;
        requireNoActiveTasks(projectId);
        setArchivedAt(projectId, Instant.now());
        return requireProject(projectId);
    }

    // 执行 ProjectService 中的 restore 处理。
    public Project restore(UUID projectId) {
        requireProject(projectId);
        setArchivedAt(projectId, null);
        return requireProject(projectId);
    }

    // 执行 ProjectService 中的 auditHistory 处理。
    public List<AuditTask> auditHistory(UUID projectId) {
        requireProject(projectId);
        return taskMapper.findByProjectIdOrderByCreatedAtDesc(projectId);
    }

    // 仅归档项目可清空扫描派生数据；裸 Git 仓库和项目基本信息继续保留。
    public CleanupResult cleanupAuditData(UUID projectId, String confirmation) {
        Project project = requireProject(projectId);
        if (!project.isArchived()) throw new IllegalArgumentException("请先归档项目，再清理扫描数据");
        if (!"DELETE_SCAN_DATA".equals(confirmation)) {
            throw new IllegalArgumentException("清理确认值不正确");
        }
        requireNoActiveTasks(projectId);
        Integer deleted = transactionTemplate.execute(status -> taskMapper.deleteByProjectId(projectId));
        return new CleanupResult(projectId, deleted == null ? 0 : deleted,
                "扫描任务及其代码块、向量、语义关系、Agent 轨迹、漏洞和报告已清理");
    }

    // 执行 ProjectService 中的 commits 处理。
    public List<GitRepositoryService.CommitInfo> commits(UUID projectId, int limit) throws IOException {
        return gitRepositoryService.commits(projectId, limit);
    }

    // 更新 refresh 对应的状态或数据。
    public List<GitRepositoryService.CommitInfo> refresh(UUID projectId, String username,
                                                         String accessToken) throws IOException {
        requireActiveProject(projectId);
        return gitRepositoryService.refresh(projectId, username, accessToken);
    }

    // 将用户选择解析为不可变提交 ID，并在同一事务中创建全量或增量任务。
    public Submission submitAudit(UUID projectId, ScanMode scanMode,
                                  String baseRevision, String targetRevision) throws IOException {
        Project project = requireActiveProject(projectId);
        ScanMode effectiveMode = scanMode == null ? ScanMode.FULL : scanMode;
        GitRepositoryService.ResolvedComparison comparison = gitRepositoryService.resolveComparison(
                project, baseRevision, targetRevision, effectiveMode == ScanMode.INCREMENTAL);
        AuditTask task = new AuditTask(projectId, effectiveMode, comparison.baseCommitSha(),
                comparison.targetCommitSha(), comparison.mergeBaseSha());
        AuditTask persisted = transactionTemplate.execute(status -> {
            taskMapper.insert(task);
            return task;
        });
        if (persisted == null) throw new IllegalStateException("创建 Git 审计任务失败");
        orchestrator.run(task.getId());
        return new Submission(project, task);
    }

    // 封装 Submission 使用的不可变结构化数据。
    public record Submission(Project project, AuditTask task) {
    }

    // 封装 CleanupResult 使用的不可变结构化数据。
    public record CleanupResult(UUID projectId, int deletedTaskCount, String message) {
    }

    // 执行 ProjectService 中的 requireProject 处理。
    private Project requireProject(UUID projectId) {
        Project project = projectMapper.findById(projectId);
        if (project == null) throw new java.util.NoSuchElementException("项目不存在: " + projectId);
        return project;
    }

    // 执行 ProjectService 中的 requireActiveProject 处理。
    private Project requireActiveProject(UUID projectId) {
        Project project = gitRepositoryService.requireGitProject(projectId);
        if (project.isArchived()) throw new IllegalArgumentException("项目已归档，请先恢复后再操作");
        return project;
    }

    // 执行 ProjectService 中的 requireNoActiveTasks 处理。
    private void requireNoActiveTasks(UUID projectId) {
        if (taskMapper.countActiveByProjectId(projectId) > 0) {
            throw new IllegalArgumentException("项目仍有运行中扫描，暂时不能归档或清理数据");
        }
    }

    // 设置 ArchivedAt 对应的状态。
    private void setArchivedAt(UUID projectId, Instant archivedAt) {
        Instant now = Instant.now();
        transactionTemplate.executeWithoutResult(status -> {
            if (projectMapper.setArchivedAt(projectId, archivedAt, now) != 1) {
                throw new IllegalStateException("更新项目归档状态失败");
            }
        });
    }

    // 规范化 normalizeName 对应的输入。
    private String normalizeName(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("项目名称不能为空");
        String normalized = value.replaceAll("[\\r\\n\\t<>]", " ").strip();
        if (normalized.isBlank()) throw new IllegalArgumentException("项目名称不能为空");
        return normalized.substring(0, Math.min(normalized.length(), 200));
    }

    // 规范化 normalizeDescription 对应的输入。
    private String normalizeDescription(String value) {
        if (value == null) return "";
        String normalized = value.replace("\u0000", "").strip();
        return normalized.substring(0, Math.min(normalized.length(), 1_000));
    }
}
