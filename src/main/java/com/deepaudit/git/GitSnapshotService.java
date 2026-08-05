package com.deepaudit.git;

import com.deepaudit.source.AuditSourceFilter;
import com.deepaudit.util.TimingDetailLog;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.FileTime;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

@Slf4j
@Service
@RequiredArgsConstructor
public class GitSnapshotService {
    private final GitProperties properties;
    private final ConcurrentHashMap<Path, ReentrantLock> cacheLocks = new ConcurrentHashMap<>();

    public SnapshotResult materializeCached(Repository repository, String commitSha,
                                            Path cacheDirectory) throws IOException {
        ObjectId resolved = repository.resolve(commitSha);
        if (resolved == null) throw new IllegalArgumentException("提交不存在: " + commitSha);
        String fullSha = resolved.name();
        Path cacheRoot = cacheDirectory.toAbsolutePath().normalize();
        Files.createDirectories(cacheRoot);
        Path destination = cacheRoot.resolve(fullSha).normalize();
        Path marker = cacheRoot.resolve(fullSha + ".snapshot").normalize();
        if (!destination.startsWith(cacheRoot) || !marker.startsWith(cacheRoot)) {
            throw new IllegalArgumentException("提交缓存路径越界");
        }
        Path lock = cacheRoot.resolve(fullSha + ".lock");
        ReentrantLock cacheLock = cacheLocks.computeIfAbsent(lock, ignored -> new ReentrantLock());
        cacheLock.lock();
        try {
            SnapshotResult cached = readCacheMarker(marker, destination, fullSha);
            if (cached != null) {
                Files.setLastModifiedTime(marker, FileTime.fromMillis(System.currentTimeMillis()));
                TimingDetailLog.info("Git 提交快照缓存命中：commit={}，files={}，bytes={}",
                        shortSha(fullSha), cached.fileCount(), cached.totalBytes());
                return cached;
            }
            deleteCachedEntry(cacheRoot, destination, marker);
            SnapshotResult result = materialize(repository, fullSha, destination);
            String metadata = result.commitSha() + "\n" + result.fileCount() + "\n"
                    + result.skippedFileCount() + "\n" + result.totalBytes();
            Files.writeString(marker, metadata, StandardCharsets.UTF_8);
            TimingDetailLog.info("Git 提交快照已写入缓存：commit={}，path={}",
                    shortSha(fullSha), destination.getFileName());
            return result;
        } finally {
            cacheLock.unlock();
            if (!cacheLock.hasQueuedThreads()) cacheLocks.remove(lock, cacheLock);
        }
    }

    public void pruneCache(Path cacheDirectory, Set<Path> protectedRoots) {
        Path cacheRoot = cacheDirectory.toAbsolutePath().normalize();
        if (!Files.isDirectory(cacheRoot)) return;
        int limit = Math.max(2, properties.getMaxCachedSnapshots());
        Set<Path> protectedNormalized = protectedRoots.stream()
                .map(path -> path.toAbsolutePath().normalize()).collect(java.util.stream.Collectors.toSet());
        try (var paths = Files.list(cacheRoot)) {
            List<Path> markers = paths.filter(path -> path.getFileName().toString().matches("[0-9a-f]{40}\\.snapshot"))
                    .sorted(Comparator.comparingLong(this::lastModified).reversed()).toList();
            int retained = 0;
            for (Path marker : markers) {
                String name = marker.getFileName().toString();
                Path root = cacheRoot.resolve(name.substring(0, 40)).normalize();
                if (protectedNormalized.contains(root) || retained++ < limit) continue;
                deleteCachedEntry(cacheRoot, root, marker);
                TimingDetailLog.info("清理过期 Git/CodeGraph 提交缓存：commit={}", name.substring(0, 8));
            }
        } catch (IOException exception) {
            log.warn("提交快照缓存清理未完整执行: {}", cacheRoot, exception);
        }
    }

    private SnapshotResult readCacheMarker(Path marker, Path destination, String fullSha) {
        if (!Files.isRegularFile(marker) || !Files.isDirectory(destination)) return null;
        try {
            List<String> values = Files.readAllLines(marker, StandardCharsets.UTF_8);
            if (values.size() != 4 || !fullSha.equals(values.get(0))) return null;
            return new SnapshotResult(fullSha, Integer.parseInt(values.get(1)),
                    Integer.parseInt(values.get(2)), Long.parseLong(values.get(3)));
        } catch (Exception exception) {
            return null;
        }
    }

    private long lastModified(Path path) {
        try {
            return Files.getLastModifiedTime(path).toMillis();
        } catch (IOException exception) {
            return 0;
        }
    }

    private void deleteCachedEntry(Path cacheRoot, Path destination, Path marker) throws IOException {
        Path normalized = destination.toAbsolutePath().normalize();
        if (normalized.startsWith(cacheRoot) && !normalized.equals(cacheRoot) && Files.exists(normalized)) {
            try (var paths = Files.walk(normalized)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
        Files.deleteIfExists(marker);
    }

    // 直接读取 Git Blob 构造快照，不执行 checkout、Hook、Submodule 或过滤器。
    public SnapshotResult materialize(Repository repository, String commitSha, Path destination) throws IOException {
        long startedAt = System.nanoTime();
        Path root = destination.toAbsolutePath().normalize();
        Files.createDirectories(root);
        TimingDetailLog.info("开始读取 Git 提交代码：commit={}，maxFiles={}，maxSnapshotBytes={}",
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
                    if (!AuditSourceFilter.classify(tree.getPathString()).materialize()) {
                        skipped++;
                        continue;
                    }
                    files++;
                    if (files % 1_000 == 0) {
                        TimingDetailLog.info("Git 提交代码读取进度：commit={}，files={}，bytes={}",
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
            TimingDetailLog.info("Git 提交代码读取完成：commit={}，files={}，skipped={}，bytes={}，elapsedMs={}",
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
