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
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.lib.Repository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
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
    private final AuditCancellationService cancellationService;

    // 按固定阶段编排 Git 快照、差异、语义索引和 Agent 审计。
    @Async("auditExecutor")
    public void run(UUID taskId) {
        long taskStarted = ExecutionTiming.start();
        AuditTask task = requireTask(taskId);
        try (AuditCancellationService.WorkerRegistration ignored = cancellationService.registerWorker(taskId)) {
            cancellationService.throwIfCancellationRequested(taskId);
            Project project = requireProject(task.getProjectId());
            log.info("开始执行增量 Git 代码读取流程：taskId={}，projectId={}，base={}，target={}",
                    taskId, project.getId(), shortSha(task.getBaseCommitSha()),
                    shortSha(task.getTargetCommitSha()));
            Path repositoryPath = Path.of(project.getStoragePath()).toAbsolutePath().normalize();
            Path projectDirectory = repositoryPath.getParent();
            Path cacheDirectory = projectDirectory.resolve("commit-cache").normalize();
            Path targetRoot = commitCacheRoot(cacheDirectory, task.getTargetCommitSha());
            Path baseRoot = commitCacheRoot(cacheDirectory, comparisonBase(task));
            List<GitFileChange> changes = List.of();

            try {
                try (Repository repository = gitRepositoryService.open(project)) {
                    task = update(task, AuditStatus.MATERIALIZING, 10,
                            "正在读取目标提交 " + shortSha(task.getTargetCommitSha()));
                    long sourceStageStarted = ExecutionTiming.start();
                    long stageStarted = ExecutionTiming.start();
                    GitSnapshotService.SnapshotResult targetSnapshot = snapshotService.materializeCached(
                            repository, task.getTargetCommitSha(), cacheDirectory);
                    TimingDetailLog.info("目标提交快照已就绪：taskId={}，commit={}，files={}，skipped={}，bytes={}",
                            taskId, shortSha(targetSnapshot.commitSha()), targetSnapshot.fileCount(),
                            targetSnapshot.skippedFileCount(), targetSnapshot.totalBytes());
                    logTiming(taskId, "TARGET_SNAPSHOT", stageStarted, taskStarted,
                            "files=" + targetSnapshot.fileCount() + ",bytes=" + targetSnapshot.totalBytes());
                    String comparisonBaseSha = comparisonBase(task);
                    stageStarted = ExecutionTiming.start();
                    GitSnapshotService.SnapshotResult baseSnapshot = snapshotService.materializeCached(
                            repository, comparisonBaseSha, cacheDirectory);
                    TimingDetailLog.info("分支变更基线快照已就绪：taskId={}，selectedBase={}，comparisonBase={}，files={}，skipped={}，bytes={}",
                            taskId, shortSha(task.getBaseCommitSha()), shortSha(baseSnapshot.commitSha()),
                            baseSnapshot.fileCount(), baseSnapshot.skippedFileCount(),
                            baseSnapshot.totalBytes());
                    logTiming(taskId, "BASE_SNAPSHOT", stageStarted, taskStarted,
                            "files=" + baseSnapshot.fileCount() + ",bytes=" + baseSnapshot.totalBytes());
                    task = update(task, AuditStatus.DIFFING, 20,
                            "正在比较 " + shortSha(comparisonBaseSha) + " → "
                                    + shortSha(task.getTargetCommitSha()));
                    stageStarted = ExecutionTiming.start();
                    GitDiffService.ChangeSet changeSet = diffService.compare(repository, taskId,
                            comparisonBaseSha, task.getTargetCommitSha());
                    TimingDetailLog.info("增量差异读取完成：taskId={}，summary={}", taskId, changeSet.summary());
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
                    logTiming(taskId, "GIT_DIFF_AND_PERSIST", stageStarted, taskStarted,
                            "changedFiles=" + changes.size());
                    log.info("阶段耗时：taskId={}，阶段=提交准备与差异读取，耗时={}ms，说明=读取Base/Target快照并计算可审计代码差异，变更文件数={}",
                            taskId, ExecutionTiming.elapsedMillis(sourceStageStarted), changes.size());

                    task = update(task, AuditStatus.INVENTORY, 28,
                            "已读取变更清单，准备增量安全上下文");
                    task = update(task, AuditStatus.INDEXING, 42,
                            "仅索引变更代码，并准备 Base/Target CodeGraph 影响分析");
                    long indexStageStarted = ExecutionTiming.start();
                    stageStarted = ExecutionTiming.start();
                    codeGraphIntegrationService.prepare(taskId, baseRoot, targetRoot);
                    logTiming(taskId, "CODEGRAPH_PREPARE", stageStarted, taskStarted, "snapshots=2");
                    stageStarted = ExecutionTiming.start();
                    var recon = reconService.buildIndex(taskId, targetRoot, baseRoot, changes);
                    logTiming(taskId, "INCREMENTAL_RECON_INDEX", stageStarted, taskStarted,
                            "changedChunks=" + recon.chunkCount());
                    log.info("阶段耗时：taskId={}，阶段=增量索引准备，耗时={}ms，说明=建立Base/Target CodeGraph索引并切分直接变更代码，变更代码块数={}",
                            taskId, ExecutionTiming.elapsedMillis(indexStageStarted), recon.chunkCount());

                    task = update(task, AuditStatus.RECON, 55,
                            "已建立 " + recon.chunkCount() + " 个直接变更代码块，影响上下文将按需加载");
                    task = update(task, AuditStatus.AGENT_RECON, 62, "Recon Agent 解析框架、模块与技术架构");
                    task = update(task, AuditStatus.PLANNING, 68, "Triage Orchestrator 正在轻量分流审计单元");
                    task = update(task, AuditStatus.ANALYSIS, 74,
                            "专业安全 Agents 调查变更及语义影响面");
                    stageStarted = ExecutionTiming.start();
                    AnalysisService.AnalysisResult analysis = analysisService.analyze(
                            taskId, targetRoot, recon, project.getName(), task);
                    logTiming(taskId, "ANALYSIS_AGENT_PIPELINE", stageStarted, taskStarted,
                            "plannedTasks=" + analysis.plannedAgentTasks() + ",findings=" + analysis.findingCount());
                    TimingDetailLog.info("阶段明细：taskId={}，阶段=智能增量审计，耗时={}ms，说明=完成影响分析、分诊、专业调查、Critic复核和报告生成，正式漏洞数={}",
                            taskId, ExecutionTiming.elapsedMillis(stageStarted), analysis.findingCount());

                    task = update(task, AuditStatus.CRITIC_REVIEW, 90, "Critic Agent 已完成独立反证复核");
                    task = update(task, AuditStatus.RESULT_VALIDATION, 94, "校验提交、文件、行号和代码证据");
                    task = update(task, AuditStatus.REPORTING, 97, "Report Agent 汇总 Git 安全审计报告");
                    update(task, AuditStatus.COMPLETED, 100,
                            "扫描完成，共发现 " + analysis.findingCount() + " 个问题");
                    log.info("阶段耗时：taskId={}，阶段=增量审计总计，耗时={}ms，说明=从提交快照读取到报告生成全部完成，正式漏洞数={}",
                            taskId, ExecutionTiming.elapsedMillis(taskStarted), analysis.findingCount());
                }
            } finally {
                // 释放任务绑定，并按提交缓存上限清理最旧的 Git/CodeGraph 快照。
                long cleanupStarted = ExecutionTiming.start();
                codeGraphIntegrationService.release(taskId);
                snapshotService.pruneCache(cacheDirectory, Set.of());
                logTiming(taskId, "RESOURCE_CLEANUP", cleanupStarted, taskStarted, "status=SUCCESS");
            }
        } catch (Exception exception) {
            if (exception instanceof AuditCancelledException
                    || cancellationService.isCancellationRequested(taskId)) {
                analysisService.discardFinalResults(taskId);
                log.info("增量审计已中断：taskId={}，elapsedMs={}，说明=停止后续分析并清除未完成的正式漏洞与报告",
                        taskId, ExecutionTiming.elapsedMillis(taskStarted));
                return;
            }
            log.error("Git 扫描任务 {} 失败；totalElapsedMs={}，errorType={}", taskId,
                    ExecutionTiming.elapsedMillis(taskStarted), exception.getClass().getSimpleName(), exception);
            AuditTask latest = requireTask(taskId);
            latest.fail(exception.getMessage());
            try {
                persistTask(latest);
            } catch (AuditCancelledException cancelled) {
                analysisService.discardFinalResults(taskId);
                log.info("任务 {} 在失败状态写入前收到中断请求，保留 CANCELLED 终态", taskId);
            }
        } finally {
            cancellationService.taskFinished(taskId);
        }
    }

    private void logTiming(UUID taskId, String stage, long stageStarted, long taskStarted, String details) {
        TimingDetailLog.info("执行耗时：taskId={}，stage={}，elapsedMs={}，totalElapsedMs={}，details={}",
                taskId, stage, ExecutionTiming.elapsedMillis(stageStarted),
                ExecutionTiming.elapsedMillis(taskStarted), details);
    }

    // 更新 update 对应的状态或数据。
    private AuditTask update(AuditTask task, AuditStatus status, int progress, String stage) {
        cancellationService.throwIfCancellationRequested(task.getId());
        task.moveTo(status, progress, stage);
        persistTask(task);
        return task;
    }

    // 保存 persistTask 对应的数据。
    private void persistTask(AuditTask task) {
        int updated = taskMapper.updateWithVersion(task);
        if (updated != 1) {
            if (cancellationService.isCancellationRequested(task.getId())) {
                throw new AuditCancelledException(task.getId());
            }
            throw new IllegalStateException("扫描任务状态已被并发修改: " + task.getId());
        }
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

    private Path commitCacheRoot(Path cacheDirectory, String commitSha) {
        String value = commitSha == null ? "" : commitSha.strip().toLowerCase(java.util.Locale.ROOT);
        if (!value.matches("[0-9a-f]{40}")) {
            throw new IllegalArgumentException("增量审计提交 ID 必须是完整 SHA-1");
        }
        Path root = cacheDirectory.toAbsolutePath().normalize();
        Path result = root.resolve(value).normalize();
        if (!result.startsWith(root)) throw new IllegalArgumentException("提交缓存路径越界");
        return result;
    }

}
