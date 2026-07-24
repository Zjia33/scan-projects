package com.deepaudit.service;

import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Project;
import com.deepaudit.domain.ScanMode;
import com.deepaudit.git.GitRepositoryService;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.orchestrator.AuditOrchestrator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Service
public class ProjectService {
    private final GitRepositoryService gitRepositoryService;
    private final AuditTaskMapper taskMapper;
    private final AuditOrchestrator orchestrator;
    private final TransactionTemplate transactionTemplate;

    public ProjectService(GitRepositoryService gitRepositoryService,
                          AuditTaskMapper taskMapper,
                          AuditOrchestrator orchestrator,
                          PlatformTransactionManager transactionManager) {
        this.gitRepositoryService = gitRepositoryService;
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

    public List<Project> projects() {
        return gitRepositoryService.projects();
    }

    public List<GitRepositoryService.CommitInfo> commits(UUID projectId, int limit) throws IOException {
        return gitRepositoryService.commits(projectId, limit);
    }

    public List<GitRepositoryService.CommitInfo> refresh(UUID projectId, String username,
                                                         String accessToken) throws IOException {
        return gitRepositoryService.refresh(projectId, username, accessToken);
    }

    // 将用户选择解析为不可变提交 ID，并在同一事务中创建全量或增量任务。
    public Submission submitAudit(UUID projectId, ScanMode scanMode,
                                  String baseRevision, String targetRevision) throws IOException {
        Project project = gitRepositoryService.requireGitProject(projectId);
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

    public record Submission(Project project, AuditTask task) {
    }
}
