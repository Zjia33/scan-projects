package com.deepaudit.git;

import com.deepaudit.source.AuditSourceFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.lib.FileMode;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectLoader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

@Slf4j
@Service
@RequiredArgsConstructor
public class GitSnapshotService {
    private final GitProperties properties;

    // 直接读取 Git Blob 构造快照，不执行 checkout、Hook、Submodule 或过滤器。
    public SnapshotResult materialize(Repository repository, String commitSha, Path destination) throws IOException {
        long startedAt = System.nanoTime();
        Path root = destination.toAbsolutePath().normalize();
        Files.createDirectories(root);
        log.info("开始读取 Git 提交代码：commit={}，maxFiles={}，maxSnapshotBytes={}",
                shortSha(commitSha), properties.getMaxFilesPerSnapshot(), properties.getMaxSnapshotBytes());
        int files = 0;
        int skipped = 0;
        int visitedFiles = 0;
        long bytes = 0;
        try (RevWalk walk = new RevWalk(repository)) {
            ObjectId objectId = repository.resolve(commitSha);
            if (objectId == null) throw new IllegalArgumentException("提交不存在: " + commitSha);
            RevCommit commit = walk.parseCommit(objectId);
            try (TreeWalk tree = new TreeWalk(repository)) {
                tree.addTree(commit.getTree());
                tree.setRecursive(true);
                while (tree.next()) {
                    FileMode mode = tree.getFileMode(0);
                    if (!FileMode.REGULAR_FILE.equals(mode) && !FileMode.EXECUTABLE_FILE.equals(mode)) {
                        skipped++;
                        continue;
                    }
                    if (++visitedFiles > properties.getMaxFilesPerSnapshot()) {
                        throw new IllegalArgumentException("Git 提交文件数超过安全上限");
                    }
                    if (!AuditSourceFilter.shouldAnalyze(tree.getPathString())) {
                        skipped++;
                        continue;
                    }
                    files++;
                    if (files % 1_000 == 0) {
                        log.info("Git 提交代码读取进度：commit={}，files={}，bytes={}",
                                shortSha(commitSha), files, bytes);
                    }
                    ObjectLoader loader = repository.open(tree.getObjectId(0));
                    long size = loader.getSize();
                    if (size > properties.getMaxFileBytes()) {
                        skipped++;
                        continue;
                    }
                    bytes += size;
                    if (bytes > properties.getMaxSnapshotBytes()) {
                        throw new IllegalArgumentException("Git 提交解包后大小超过安全上限");
                    }
                    Path output = root.resolve(tree.getPathString()).normalize();
                    if (!output.startsWith(root)) throw new IllegalArgumentException("Git 路径越界");
                    Files.createDirectories(output.getParent());
                    try (InputStream input = loader.openStream()) {
                        Files.copy(input, output);
                    }
                }
            }
            SnapshotResult result = new SnapshotResult(commit.getId().name(), files, skipped, bytes);
            log.info("Git 提交代码读取完成：commit={}，files={}，skipped={}，bytes={}，elapsedMs={}",
                    shortSha(result.commitSha()), result.fileCount(), result.skippedFileCount(),
                    result.totalBytes(), elapsedMillis(startedAt));
            return result;
        }
    }

    private String shortSha(String sha) {
        return sha == null ? "" : sha.substring(0, Math.min(8, sha.length()));
    }

    private long elapsedMillis(long startedAt) {
        return (System.nanoTime() - startedAt) / 1_000_000;
    }

    public record SnapshotResult(String commitSha, int fileCount, int skippedFileCount, long totalBytes) {
    }
}
