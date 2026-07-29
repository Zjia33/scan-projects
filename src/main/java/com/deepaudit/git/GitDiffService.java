package com.deepaudit.git;

import com.deepaudit.domain.GitFileChange;
import com.deepaudit.source.AuditSourceFilter;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.RawText;
import org.eclipse.jgit.diff.RawTextComparator;
import org.eclipse.jgit.lib.AbbreviatedObjectId;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.diff.Edit;
import org.eclipse.jgit.patch.FileHeader;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;
import org.eclipse.jgit.util.io.DisabledOutputStream;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

// 负责 GitDiffService 对应的业务编排和处理。
@Slf4j
@Service
public class GitDiffService {
    private static final int MAX_CONTEXT_CHARS = 12_000;
    private static final long MAX_DIFF_BLOB_BYTES = 2L * 1024L * 1024L;

    // 执行 GitDiffService 中的 compare 处理。
    public ChangeSet compare(Repository repository, UUID taskId,
                             String baseCommitSha, String targetCommitSha) throws IOException {
        long startedAt = System.nanoTime();
        log.info("开始读取 Git 提交差异：taskId={}，base={}，target={}",
                taskId, shortSha(baseCommitSha), shortSha(targetCommitSha));
        List<GitFileChange> changes = new ArrayList<>();
        try (RevWalk walk = new RevWalk(repository);
             ObjectReader reader = repository.newObjectReader();
             DiffFormatter formatter = new DiffFormatter(DisabledOutputStream.INSTANCE)) {
            RevCommit base = walk.parseCommit(require(repository, baseCommitSha));
            RevCommit target = walk.parseCommit(require(repository, targetCommitSha));
            CanonicalTreeParser oldTree = new CanonicalTreeParser();
            oldTree.reset(reader, base.getTree());
            CanonicalTreeParser newTree = new CanonicalTreeParser();
            newTree.reset(reader, target.getTree());
            formatter.setRepository(repository);
            formatter.setDiffComparator(RawTextComparator.DEFAULT);
            formatter.setDetectRenames(true);
            for (DiffEntry entry : formatter.scan(oldTree, newTree)) {
                String oldPath = path(entry.getOldPath());
                String newPath = path(entry.getNewPath());
                if (!AuditSourceFilter.shouldAnalyze(oldPath)
                        && !AuditSourceFilter.shouldAnalyze(newPath)) {
                    continue;
                }
                FileHeader header = formatter.toFileHeader(entry);
                int additions = 0;
                int deletions = 0;
                List<String> oldRanges = new ArrayList<>();
                List<String> newRanges = new ArrayList<>();
                String oldText = readText(repository, entry.getOldId());
                String newText = readText(repository, entry.getNewId());
                StringBuilder context = new StringBuilder();
                for (Edit edit : header.toEditList()) {
                    additions += edit.getLengthB();
                    deletions += edit.getLengthA();
                    if (edit.getLengthA() > 0) oldRanges.add(range(edit.getBeginA(), edit.getEndA()));
                    if (edit.getLengthB() > 0) newRanges.add(range(edit.getBeginB(), edit.getEndB()));
                    appendEditContext(context, edit, oldText, newText);
                }
                String effectivePath = newPath == null ? oldPath : newPath;
                changes.add(new GitFileChange(taskId, oldPath, newPath, entry.getChangeType().name(),
                        additions, deletions, String.join(",", oldRanges), String.join(",", newRanges),
                        truncate(context.toString()), isConfiguration(effectivePath)));
            }
        }
        int additions = changes.stream().mapToInt(GitFileChange::getAdditions).sum();
        int deletions = changes.stream().mapToInt(GitFileChange::getDeletions).sum();
        long configurations = changes.stream().filter(GitFileChange::isConfigurationChange).count();
        String summary = changes.size() + " 个文件发生变化，新增 " + additions + " 行、删除 "
                + deletions + " 行，其中 " + configurations + " 个配置或依赖文件";
        log.info("Git 提交差异读取完成：taskId={}，changedFiles={}，additions={}，deletions={}，"
                        + "configurationFiles={}，elapsedMs={}",
                taskId, changes.size(), additions, deletions, configurations, elapsedMillis(startedAt));
        return new ChangeSet(List.copyOf(changes), summary, additions, deletions);
    }

    // 执行 GitDiffService 中的 require 处理。
    private ObjectId require(Repository repository, String revision) throws IOException {
        ObjectId value = repository.resolve(revision);
        if (value == null) throw new IllegalArgumentException("提交不存在: " + revision);
        return value;
    }

    // 读取并返回 readText 对应的信息。
    private String readText(Repository repository, AbbreviatedObjectId abbreviated) {
        if (abbreviated == null || abbreviated.toObjectId().equals(ObjectId.zeroId())) return "";
        try {
            var loader = repository.open(abbreviated.toObjectId());
            if (loader.getSize() > MAX_DIFF_BLOB_BYTES) return "";
            byte[] bytes = loader.getBytes((int) MAX_DIFF_BLOB_BYTES);
            if (RawText.isBinary(bytes)) return "";
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception exception) {
            return "";
        }
    }

    // 向当前结果添加 appendEditContext 对应的数据。
    private void appendEditContext(StringBuilder target, Edit edit, String oldText, String newText) {
        if (target.length() >= MAX_CONTEXT_CHARS) return;
        String[] oldLines = oldText.split("\\R", -1);
        String[] newLines = newText.split("\\R", -1);
        target.append("@@ base ").append(edit.getBeginA() + 1).append("-").append(edit.getEndA())
                .append(" target ").append(edit.getBeginB() + 1).append("-").append(edit.getEndB())
                .append(" @@\n");
        for (int index = edit.getBeginA(); index < edit.getEndA() && index < oldLines.length; index++) {
            target.append("- ").append(oldLines[index]).append('\n');
            if (target.length() >= MAX_CONTEXT_CHARS) return;
        }
        for (int index = edit.getBeginB(); index < edit.getEndB() && index < newLines.length; index++) {
            target.append("+ ").append(newLines[index]).append('\n');
            if (target.length() >= MAX_CONTEXT_CHARS) return;
        }
    }

    // 执行 GitDiffService 中的 range 处理。
    private String range(int zeroBasedBegin, int zeroBasedEndExclusive) {
        return (zeroBasedBegin + 1) + ":" + Math.max(zeroBasedBegin + 1, zeroBasedEndExclusive);
    }

    // 执行 GitDiffService 中的 path 处理。
    private String path(String value) {
        return value == null || DiffEntry.DEV_NULL.equals(value) ? null : value.replace('\\', '/');
    }

    // 判断是否满足 isConfiguration 对应的条件。
    private boolean isConfiguration(String path) {
        if (path == null) return false;
        String normalized = path.toLowerCase(Locale.ROOT);
        String name = normalized.substring(normalized.lastIndexOf('/') + 1);
        return name.equals("pom.xml") || name.startsWith("build.gradle") || name.startsWith("settings.gradle")
                || name.equals("application.yml") || name.equals("application.yaml")
                || normalized.endsWith(".xml") || normalized.endsWith(".yml") || normalized.endsWith(".yaml")
                || normalized.endsWith(".properties") || normalized.endsWith(".sql");
    }

    // 执行 GitDiffService 中的 truncate 处理。
    private String truncate(String value) {
        return value.substring(0, Math.min(value.length(), MAX_CONTEXT_CHARS));
    }

    // 执行 GitDiffService 中的 shortSha 处理。
    private String shortSha(String sha) {
        return sha == null ? "" : sha.substring(0, Math.min(8, sha.length()));
    }

    // 执行 GitDiffService 中的 elapsedMillis 处理。
    private long elapsedMillis(long startedAt) {
        return (System.nanoTime() - startedAt) / 1_000_000;
    }

    // 封装 ChangeSet 使用的不可变结构化数据。
    public record ChangeSet(List<GitFileChange> changes, String summary, int additions, int deletions) {
    }
}
