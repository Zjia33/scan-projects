package com.deepaudit.orchestrator;

import com.deepaudit.analysis.AnalysisService;
import com.deepaudit.domain.AuditStatus;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Project;
import com.deepaudit.recon.ReconService;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.ProjectMapper;
import com.deepaudit.storage.SafeZipExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.UUID;

@Service
public class AuditOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(AuditOrchestrator.class);

    private final ProjectMapper projectMapper;
    private final AuditTaskMapper taskMapper;
    private final SafeZipExtractor zipExtractor;
    private final ReconService reconService;
    private final AnalysisService analysisService;

    public AuditOrchestrator(ProjectMapper projectMapper,
                             AuditTaskMapper taskMapper,
                             SafeZipExtractor zipExtractor,
                             ReconService reconService,
                             AnalysisService analysisService) {
        this.projectMapper = projectMapper;
        this.taskMapper = taskMapper;
        this.zipExtractor = zipExtractor;
        this.reconService = reconService;
        this.analysisService = analysisService;
    }

    // 按固定阶段编排一次扫描，并持续持久化可观察的任务进度。
    @Async("auditExecutor")
    public void run(UUID taskId) {
        AuditTask task = requireTask(taskId);
        try {
            // 从已保存的 ZIP 推导本任务独占且规范化的解压目录。
            Project project = requireProject(task.getProjectId());
            Path zipFile = Path.of(project.getStoragePath()).toAbsolutePath().normalize();
            Path projectRoot = zipFile.getParent().resolve("workspace-" + taskId).normalize();

            // 第一阶段安全解压，所有后续分析都只读取隔离工作区。
            task = update(task, AuditStatus.EXTRACTING, 10, "安全解压 ZIP");
            SafeZipExtractor.ExtractionResult extraction = zipExtractor.extract(zipFile, projectRoot);

            // 第二阶段盘点源码并建立代码块、向量和技术栈索引。
            task = update(task, AuditStatus.INVENTORY, 25,
                    "项目盘点：" + extraction.fileCount() + " 个文件");
            task = update(task, AuditStatus.INDEXING, 40, "解析代码并建立 RAG 索引");
            var recon = reconService.buildIndex(taskId, projectRoot);

            // 第三阶段执行 Recon、计划、专业调查、Critic 与报告 Agent 链路。
            task = update(task, AuditStatus.RECON, 55,
                    "识别到 " + recon.endpointCount() + " 个接口、" + recon.javaMethodCount() + " 个 Java 方法");
            task = update(task, AuditStatus.AGENT_RECON, 62, "Recon Agent 理解架构与攻击面");
            task = update(task, AuditStatus.PLANNING, 68, "Orchestrator Agent 制定审计计划");
            task = update(task, AuditStatus.ANALYSIS, 74, "专业安全 Agents 多轮调查代码");
            AnalysisService.AnalysisResult analysis = analysisService.analyze(
                    taskId, projectRoot, recon, project.getName());
            int findingCount = analysis.findingCount();

            // 第四阶段记录复核、证据校验和报告状态后完成任务。
            task = update(task, AuditStatus.CRITIC_REVIEW, 90, "Critic Agent 已完成独立反证复核");
            task = update(task, AuditStatus.RESULT_VALIDATION, 94, "校验 Agent 引用的文件、行号和代码证据");
            task = update(task, AuditStatus.REPORTING, 97, "Report Agent 汇总审计报告");
            update(task, AuditStatus.COMPLETED, 100, "扫描完成，共发现 " + findingCount + " 个问题");
        } catch (Exception exception) {
            // 任一阶段失败都转换为持久化 FAILED 状态，供 API 和 SSE 展示。
            log.error("扫描任务 {} 失败", taskId, exception);
            task.fail(exception.getMessage());
            persistTask(task);
        }
    }

    // 原子推进任务状态并返回带新版本号的任务对象。
    private AuditTask update(AuditTask task, AuditStatus status, int progress, String stage) {
        task.moveTo(status, progress, stage);
        persistTask(task);
        return task;
    }

    // 使用乐观锁保存进度，防止并发执行覆盖较新的任务状态。
    private void persistTask(AuditTask task) {
        int updated = taskMapper.updateWithVersion(task);
        if (updated != 1) {
            throw new IllegalStateException("扫描任务状态已被并发修改: " + task.getId());
        }
        task.setVersion(task.getVersion() + 1);
    }

    // 读取扫描任务，不存在时立即终止编排。
    private AuditTask requireTask(UUID taskId) {
        AuditTask task = taskMapper.findById(taskId);
        if (task == null) throw new java.util.NoSuchElementException("扫描任务不存在: " + taskId);
        return task;
    }

    // 读取任务所属项目，不存在时立即终止编排。
    private Project requireProject(UUID projectId) {
        Project project = projectMapper.findById(projectId);
        if (project == null) throw new java.util.NoSuchElementException("项目不存在: " + projectId);
        return project;
    }
}
