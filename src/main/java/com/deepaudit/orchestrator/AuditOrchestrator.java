package com.deepaudit.orchestrator;

import com.deepaudit.analysis.AnalysisService;
import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.domain.AuditStatus;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.Project;
import com.deepaudit.git.GitDiffService;
import com.deepaudit.git.GitRepositoryService;
import com.deepaudit.git.GitSnapshotService;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.ProjectMapper;
import com.deepaudit.recon.ReconService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.lib.Repository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

// 封装 AuditOrchestrator 相关的数据与处理逻辑。
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditOrchestrator {
    private final ProjectMapper projectMapper;
    private final AuditTaskMapper taskMapper;
    private final GitFileChangeMapper changeMapper;
    private final GitRepositoryService gitRepositoryService;
    private final GitSnapshotService snapshotService;
    private final GitDiffService diffService;
    private final ReconService reconService;
    private final AnalysisService analysisService;
    private final CodeGraphIntegrationService codeGraphIntegrationService;

    // 按固定阶段编排 Git 快照、差异、语义索引和 Agent 审计。
    @Async("auditExecutor")
    public void run(UUID taskId) {
        AuditTask task = requireTask(taskId);
        try {
            Project project = requireProject(task.getProjectId());
            log.info("开始执行增量 Git 代码读取流程：taskId={}，projectId={}，base={}，target={}",
                    taskId, project.getId(), shortSha(task.getBaseCommitSha()),
                    shortSha(task.getTargetCommitSha()));
            Path repositoryPath = Path.of(project.getStoragePath()).toAbsolutePath().normalize();
            Path projectDirectory = repositoryPath.getParent();
            Path targetRoot = projectDirectory.resolve("workspace-" + taskId + "-target").normalize();
            Path baseRoot = projectDirectory.resolve("workspace-" + taskId + "-base").normalize();
            List<GitFileChange> changes = List.of();

            try {
                try (Repository repository = gitRepositoryService.open(project)) {
                    task = update(task, AuditStatus.MATERIALIZING, 10,
                            "正在读取目标提交 " + shortSha(task.getTargetCommitSha()));
                    GitSnapshotService.SnapshotResult targetSnapshot = snapshotService.materialize(
                            repository, task.getTargetCommitSha(), targetRoot);
                    log.info("目标提交快照已就绪：taskId={}，commit={}，files={}，skipped={}，bytes={}",
                            taskId, shortSha(targetSnapshot.commitSha()), targetSnapshot.fileCount(),
                            targetSnapshot.skippedFileCount(), targetSnapshot.totalBytes());
                    String comparisonBaseSha = comparisonBase(task);
                    GitSnapshotService.SnapshotResult baseSnapshot = snapshotService.materialize(
                            repository, comparisonBaseSha, baseRoot);
                    log.info("分支变更基线快照已就绪：taskId={}，selectedBase={}，comparisonBase={}，files={}，skipped={}，bytes={}",
                            taskId, shortSha(task.getBaseCommitSha()), shortSha(baseSnapshot.commitSha()),
                            baseSnapshot.fileCount(), baseSnapshot.skippedFileCount(),
                            baseSnapshot.totalBytes());
                    task = update(task, AuditStatus.DIFFING, 20,
                            "正在比较 " + shortSha(comparisonBaseSha) + " → "
                                    + shortSha(task.getTargetCommitSha()));
                    GitDiffService.ChangeSet changeSet = diffService.compare(repository, taskId,
                            comparisonBaseSha, task.getTargetCommitSha());
                    log.info("增量差异读取完成：taskId={}，summary={}", taskId, changeSet.summary());
                    changes = changeSet.changes();
                    task.setChangeSummary(changeSet.summary());
                    persistTask(task);
                    changeMapper.deleteByTaskId(taskId);
                    for (int start = 0; start < changes.size(); start += 300) {
                        changeMapper.insertBatch(changes.subList(start, Math.min(start + 300, changes.size())));
                    }
                    if (changes.isEmpty()) {
                        throw new IllegalArgumentException("两个提交之间没有可审计的生产代码或配置变化");
                    }

                    task = update(task, AuditStatus.INVENTORY, 28,
                            "项目盘点：" + targetSnapshot.fileCount() + " 个文件");
                    task = update(task, AuditStatus.INDEXING, 42,
                            "构建 Base/Target 方法差异、CodeGraph 拓扑和增量语义索引");
                    var recon = reconService.buildIndex(taskId, targetRoot, baseRoot, changes);

                    task = update(task, AuditStatus.RECON, 55,
                            "识别到 " + recon.endpointCount() + " 个接口、" + recon.javaMethodCount() + " 个 Java 方法");
                    task = update(task, AuditStatus.AGENT_RECON, 62, "Recon Agent 解析框架、模块与技术架构");
                    task = update(task, AuditStatus.PLANNING, 68, "Triage Orchestrator 正在轻量分流审计单元");
                    task = update(task, AuditStatus.ANALYSIS, 74,
                            "专业安全 Agents 调查变更及语义影响面");
                    AnalysisService.AnalysisResult analysis = analysisService.analyze(
                            taskId, targetRoot, baseRoot, recon, project.getName(), task);

                    task = update(task, AuditStatus.CRITIC_REVIEW, 90, "Critic Agent 已完成独立反证复核");
                    task = update(task, AuditStatus.RESULT_VALIDATION, 94, "校验提交、文件、行号和代码证据");
                    task = update(task, AuditStatus.REPORTING, 97, "Report Agent 汇总 Git 安全审计报告");
                    update(task, AuditStatus.COMPLETED, 100,
                            "扫描完成，共发现 " + analysis.findingCount() + " 个问题");
                }
            } finally {
                // Chunk、Diff 和报告证据已持久化，任务结束后删除临时快照以避免磁盘持续增长。
                codeGraphIntegrationService.release(taskId);
                deleteWorkspace(projectDirectory, targetRoot);
                deleteWorkspace(projectDirectory, baseRoot);
            }
        } catch (Exception exception) {
            log.error("Git 扫描任务 {} 失败", taskId, exception);
            task.fail(exception.getMessage());
            persistTask(task);
        }
    }

    // 更新 update 对应的状态或数据。
    private AuditTask update(AuditTask task, AuditStatus status, int progress, String stage) {
        task.moveTo(status, progress, stage);
        persistTask(task);
        return task;
    }

    // 保存 persistTask 对应的数据。
    private void persistTask(AuditTask task) {
        int updated = taskMapper.updateWithVersion(task);
        if (updated != 1) throw new IllegalStateException("扫描任务状态已被并发修改: " + task.getId());
        task.setVersion(task.getVersion() + 1);
    }

    // 执行 AuditOrchestrator 中的 comparisonBase 处理。
    private String comparisonBase(AuditTask task) {
        return task.getMergeBaseSha() == null || task.getMergeBaseSha().isBlank()
                ? task.getBaseCommitSha() : task.getMergeBaseSha();
    }

    // 执行 AuditOrchestrator 中的 requireTask 处理。
    private AuditTask requireTask(UUID taskId) {
        AuditTask task = taskMapper.findById(taskId);
        if (task == null) throw new java.util.NoSuchElementException("扫描任务不存在: " + taskId);
        return task;
    }

    // 执行 AuditOrchestrator 中的 requireProject 处理。
    private Project requireProject(UUID projectId) {
        Project project = projectMapper.findById(projectId);
        if (project == null) throw new java.util.NoSuchElementException("项目不存在: " + projectId);
        return project;
    }

    // 执行 AuditOrchestrator 中的 shortSha 处理。
    private String shortSha(String value) {
        return value == null ? "" : value.substring(0, Math.min(8, value.length()));
    }

    // 清理或删除 deleteWorkspace 对应的数据。
    private void deleteWorkspace(Path projectDirectory, Path workspace) {
        Path parent = projectDirectory.toAbsolutePath().normalize();
        Path target = workspace.toAbsolutePath().normalize();
        if (!target.startsWith(parent) || target.equals(parent) || !Files.exists(target)) return;
        try (var paths = Files.walk(target)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException exception) {
            log.warn("无法清理任务临时快照 {}", target, exception);
        }
    }
}
