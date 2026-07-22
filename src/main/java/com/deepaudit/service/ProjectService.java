package com.deepaudit.service;

import com.deepaudit.domain.AuditTask;
import com.deepaudit.domain.Project;
import com.deepaudit.orchestrator.AuditOrchestrator;
import com.deepaudit.mapper.AuditTaskMapper;
import com.deepaudit.mapper.ProjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.UUID;

@Service
public class ProjectService {

    private static final long MAX_ZIP_BYTES = 200L * 1024L * 1024L;

    private final ProjectMapper projectMapper;
    private final AuditTaskMapper taskMapper;
    private final AuditOrchestrator orchestrator;
    private final Path storageRoot;
    private final TransactionTemplate transactionTemplate;

    public ProjectService(ProjectMapper projectMapper,
                          AuditTaskMapper taskMapper,
                          AuditOrchestrator orchestrator,
                          PlatformTransactionManager transactionManager,
                          @Value("${deepaudit.storage-root:./data}") String storageRoot) {
        this.projectMapper = projectMapper;
        this.taskMapper = taskMapper;
        this.orchestrator = orchestrator;
        this.storageRoot = Path.of(storageRoot).toAbsolutePath().normalize();
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    // 校验并持久化上传项目，创建任务后交给异步编排器启动完整扫描。
    public Submission submit(String requestedName, MultipartFile file) throws IOException {
        // 先在写盘前拦截空文件、错误格式和超大 ZIP。
        validate(file);
        UUID projectId = UUID.randomUUID();
        Path projectDirectory = storageRoot.resolve("projects").resolve(projectId.toString()).normalize();
        if (!projectDirectory.startsWith(storageRoot)) {
            throw new IOException("项目存储路径非法");
        }
        // 将原始 ZIP 保存到项目隔离目录，后续扫描只使用该受控路径。
        Files.createDirectories(projectDirectory);
        Path zipPath = projectDirectory.resolve("source.zip");
        try (var input = file.getInputStream()) {
            Files.copy(input, zipPath, StandardCopyOption.REPLACE_EXISTING);
        }

        String originalFilename = file.getOriginalFilename() == null ? "project.zip" : file.getOriginalFilename();
        String name = sanitizeName(requestedName == null || requestedName.isBlank()
                ? originalFilename.substring(0, Math.max(1, originalFilename.length() - 4)) : requestedName);
        // 在同一事务中创建项目与扫描任务，避免出现无任务的孤立项目。
        Submission submission = transactionTemplate.execute(status -> {
            Project project = new Project(projectId, name, originalFilename, zipPath.toString());
            projectMapper.insert(project);
            AuditTask task = new AuditTask(project.getId());
            taskMapper.insert(task);
            return new Submission(project, task);
        });
        if (submission == null) {
            throw new IllegalStateException("创建扫描任务失败");
        }
        // 事务提交后异步启动扫描，使上传请求可以立即返回任务标识。
        orchestrator.run(submission.task().getId());
        return submission;
    }

    // 对上传文件执行入口级类型和大小限制。
    private void validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("请选择非空 ZIP 文件");
        }
        String filename = file.getOriginalFilename() == null ? "" : file.getOriginalFilename().toLowerCase(Locale.ROOT);
        if (!filename.endsWith(".zip")) {
            throw new IllegalArgumentException("第一版仅支持 ZIP 文件");
        }
        if (file.getSize() > MAX_ZIP_BYTES) {
            throw new IllegalArgumentException("ZIP 文件不能超过 200MB");
        }
    }

    // 清理项目展示名称中的控制字符并限制数据库字段长度。
    private String sanitizeName(String value) {
        String sanitized = value.replaceAll("[\\r\\n\\t<>]", " ").strip();
        if (sanitized.isBlank()) return "未命名项目";
        return sanitized.substring(0, Math.min(200, sanitized.length()));
    }

    public record Submission(Project project, AuditTask task) {
    }
}
