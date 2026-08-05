package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 管理任务级 CodeGraph 索引，并向专业 Agent 提供按需、分页的符号关系候选。
 * CodeGraph 不再预先扩张审计范围；只有模型明确选择的位置才会物化为源码上下文。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CodeGraphIntegrationService {
    private final CodeGraphProperties properties;
    private final CodeGraphClient client;
    private final CodeGraphResultMapper resultMapper;
    private final Set<UUID> preparedTasks = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Path> targetRoots = new ConcurrentHashMap<>();
    private final Map<UUID, Map<String, ImpactCandidate>> candidates = new ConcurrentHashMap<>();
    private final Map<UUID, Map<QueryKey, QueryCache>> candidatePages = new ConcurrentHashMap<>();
    private final Map<UUID, Object> materializationLocks = new ConcurrentHashMap<>();
    private final Set<UUID> globalContextMaterialized = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Set<String>> projectSearches = new ConcurrentHashMap<>();

    /** 为不可变 Target 提交建立临时调用关系索引；Base 只用于本地差异比较。 */
    public boolean prepare(UUID taskId, Path targetRoot) {
        if (targetRoot != null) targetRoots.put(taskId, targetRoot.toAbsolutePath().normalize());
        if (!properties.isEnabled()) return false;
        boolean target = prepareTarget(taskId, targetRoot);
        return target;
    }

    private boolean prepareTarget(UUID taskId, Path root) {
        if (preparedTasks.contains(taskId)) return true;
        TimingDetailLog.info("任务 {} 开始准备 CodeGraph Target 索引，workspace={}",
                taskId, root == null ? "-" : root.getFileName());
        try {
            client.prepare(taskId, root);
            preparedTasks.add(taskId);
            TimingDetailLog.info("任务 {} CodeGraph Target 索引已就绪", taskId);
            return true;
        } catch (RuntimeException exception) {
            preparedTasks.remove(taskId);
            safeClientRelease(taskId);
            throw new CodeGraphException("CodeGraph Target 索引建立失败: "
                    + exception.getMessage(), exception);
        }
    }

    /**
     * 只返回直接调用者/被调用者的符号和位置，不读取源码。cursor 是零基偏移量。
     */
    public CandidatePage relatedCandidates(UUID taskId, CodeChunk anchor, Direction direction,
                                           int cursor, int requestedLimit) {
        if (!preparedTasks.contains(taskId) || anchor == null
                || anchor.getChunkType() == null
                || !anchor.getChunkType().startsWith("JAVA_METHOD")) return CandidatePage.empty();
        String symbol = codeGraphSymbol(anchor.getSymbolName());
        if (symbol.isBlank()) return CandidatePage.empty();
        int limit = Math.max(1, Math.min(requestedLimit, properties.getAgentContextLimit()));
        int offset = Math.max(0, cursor);
        try {
            QueryKey queryKey = new QueryKey(anchor.getId(), direction);
            Map<QueryKey, QueryCache> taskPages = candidatePages.computeIfAbsent(taskId,
                    ignored -> new ConcurrentHashMap<>());
            int desiredLimit = Math.min(1000, Math.max(safeRelationLimit(), offset + limit));
            QueryCache cache = taskPages.get(queryKey);
            if (cache == null || cache.sourceTruncated() && cache.fetchedLimit() < desiredLimit) {
                synchronized (materializationLock(taskId)) {
                    cache = taskPages.get(queryKey);
                    if (cache == null || cache.sourceTruncated() && cache.fetchedLimit() < desiredLimit) {
                        int fetchLimit = cache == null ? desiredLimit
                                : Math.min(1000, Math.max(desiredLimit, cache.fetchedLimit() * 2));
                        cache = loadCandidates(taskId, anchor, direction, symbol, fetchLimit);
                        taskPages.put(queryKey, cache);
                    }
                }
            }
            List<ImpactCandidate> all = cache.candidates();
            int from = Math.min(offset, all.size());
            int to = Math.min(from + limit, all.size());
            boolean canFetchMore = cache.sourceTruncated() && cache.fetchedLimit() < 1000;
            boolean truncated = to < all.size() || cache.sourceTruncated();
            String nextCursor = to < all.size() || canFetchMore ? String.valueOf(to) : null;
            return new CandidatePage(List.copyOf(all.subList(from, to)), all.size(), truncated,
                    nextCursor);
        } catch (RuntimeException exception) {
            log.warn("任务 {} CodeGraph 符号候选查询失败，anchor={}，原因={}",
                    taskId, anchor.getId(), exception.getMessage());
            return CandidatePage.failed("CodeGraph 符号候选查询失败: " + exception.getMessage());
        }
    }

    private QueryCache loadCandidates(UUID taskId, CodeChunk anchor, Direction direction,
                                      String symbol, int fetchLimit) {
        CodeGraphClient.RelatedLocations related = client.related(taskId, symbol, fetchLimit);
        List<ImpactCandidate> loaded = new ArrayList<>();
        boolean sourceTruncated = false;
        if (direction != Direction.CALLEES) {
            addCandidates(taskId, anchor, Direction.CALLERS, related.callers(), loaded);
            sourceTruncated |= related.callersTruncated();
        }
        if (direction != Direction.CALLERS) {
            addCandidates(taskId, anchor, Direction.CALLEES, related.callees(), loaded);
            sourceTruncated |= related.calleesTruncated();
        }
        return new QueryCache(List.copyOf(loaded), fetchLimit, sourceTruncated);
    }

    private void addCandidates(UUID taskId, CodeChunk anchor, Direction direction,
                               List<CodeGraphClient.CodeGraphLocation> locations,
                               List<ImpactCandidate> result) {
        Map<String, ImpactCandidate> taskCandidates = candidates.computeIfAbsent(taskId,
                ignored -> new ConcurrentHashMap<>());
        Map<String, ImpactCandidate> unique = new LinkedHashMap<>();
        for (CodeGraphClient.CodeGraphLocation location : locations) {
            if (location == null || location.filePath() == null || location.filePath().isBlank()) continue;
            String seed = anchor.getId() + "|" + direction + "|" + normalize(location.filePath())
                    + "|" + location.startLine() + "|" + location.name();
            String id = UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
            ImpactCandidate candidate = new ImpactCandidate(id, anchor.getId(), direction, location);
            taskCandidates.putIfAbsent(id, candidate);
            unique.putIfAbsent(id, candidate);
        }
        result.addAll(unique.values());
    }

    public ImpactCandidate candidate(UUID taskId, String candidateId) {
        if (candidateId == null) return null;
        return candidates.getOrDefault(taskId, Map.of()).get(candidateId);
    }

    public Path targetRoot(UUID taskId) {
        return targetRoots.get(taskId);
    }

    public Object materializationLock(UUID taskId) {
        return materializationLocks.computeIfAbsent(taskId, ignored -> new Object());
    }

    public boolean isGlobalContextMaterialized(UUID taskId) {
        return globalContextMaterialized.contains(taskId);
    }

    public void markGlobalContextMaterialized(UUID taskId) {
        globalContextMaterialized.add(taskId);
    }

    public boolean markProjectSearchIfNew(UUID taskId, String searchKey) {
        return projectSearches.computeIfAbsent(taskId, ignored -> ConcurrentHashMap.newKeySet())
                .add(searchKey);
    }

    /** 将一个已经物化的位置严格映射到唯一代码块。 */
    public CodeChunk mapCandidate(List<CodeChunk> chunks, ImpactCandidate candidate) {
        return candidate == null ? null : resultMapper.mapLocation(chunks, candidate.location());
    }

    /** CodeGraph 复验直接关系；调用点真实性还需由本地符号事实共同确认。 */
    public RelationCheck verifyDirectRelation(UUID taskId, CodeChunk current, CodeChunk candidate,
                                              List<CodeChunk> chunks) {
        if (!preparedTasks.contains(taskId) || current == null || candidate == null
                || current.getChunkType() == null || !current.getChunkType().startsWith("JAVA_METHOD")
                || candidate.getChunkType() == null || !candidate.getChunkType().startsWith("JAVA_METHOD")) {
            return RelationCheck.unverified("CodeGraph Target 索引未就绪或待验证对象不是 Java 方法");
        }
        String symbol = codeGraphSymbol(current.getSymbolName());
        if (symbol.isBlank()) return RelationCheck.unverified("当前代码块没有可查询的 CodeGraph 符号");
        try {
            CodeGraphClient.RelatedLocations related = client.related(
                    taskId, symbol, 1000);
            List<CodeGraphClient.CodeGraphLocation> locations = new ArrayList<>();
            locations.addAll(related.callers());
            locations.addAll(related.callees());
            boolean verified = candidate.getId() != null
                    && resultMapper.map(chunks, locations).chunkIds().contains(candidate.getId());
            return verified
                    ? new RelationCheck(true, "CodeGraph Target 索引命中直接调用关系")
                    : RelationCheck.unverified("CodeGraph 未确认两个方法存在直接调用关系");
        } catch (RuntimeException exception) {
            log.warn("任务 {} CodeGraph 直接关系复验失败：{} <-> {}，原因={}",
                    taskId, current.getId(), candidate.getId(), exception.getMessage());
            return RelationCheck.unverified("CodeGraph 关系验证失败");
        }
    }

    public void release(UUID taskId) {
        boolean prepared = preparedTasks.remove(taskId);
        targetRoots.remove(taskId);
        candidates.remove(taskId);
        candidatePages.remove(taskId);
        materializationLocks.remove(taskId);
        globalContextMaterialized.remove(taskId);
        projectSearches.remove(taskId);
        safeClientRelease(taskId);
        if (prepared) TimingDetailLog.info("任务 {} CodeGraph Target 临时索引已释放", taskId);
    }

    private void safeClientRelease(UUID taskId) {
        try {
            client.release(taskId);
        } catch (RuntimeException exception) {
            log.warn("任务 {} 释放 CodeGraph 状态失败：{}", taskId, exception.getMessage());
        }
    }

    private int safeRelationLimit() {
        return Math.max(1, Math.min(properties.getRelationLimit(), 1000));
    }

    private String codeGraphSymbol(String value) {
        if (value == null) return "";
        String symbol = value.strip();
        int parameters = symbol.indexOf('(');
        if (parameters >= 0) symbol = symbol.substring(0, parameters);
        return symbol.replace('#', '.');
    }

    private String normalize(String value) {
        return value == null ? "" : value.replace('\\', '/').strip();
    }

    public enum Direction { CALLERS, CALLEES, BOTH }

    private record QueryKey(Long anchorChunkId, Direction direction) {
    }

    private record QueryCache(List<ImpactCandidate> candidates, int fetchedLimit,
                              boolean sourceTruncated) {
    }

    public record ImpactCandidate(String candidateId, Long anchorChunkId, Direction direction,
                                  CodeGraphClient.CodeGraphLocation location) {
    }

    public record CandidatePage(List<ImpactCandidate> candidates, int total,
                                boolean truncated, String nextCursor, String error) {
        public CandidatePage {
            candidates = candidates == null ? List.of() : List.copyOf(candidates);
            error = error == null || error.isBlank() ? null : error;
        }

        public CandidatePage(List<ImpactCandidate> candidates, int total,
                             boolean truncated, String nextCursor) {
            this(candidates, total, truncated, nextCursor, null);
        }

        public static CandidatePage empty() {
            return new CandidatePage(List.of(), 0, false, null, null);
        }

        public static CandidatePage failed(String error) {
            return new CandidatePage(List.of(), 0, false, null, error);
        }
    }

    public record RelationCheck(boolean verified, String reason) {
        public static RelationCheck unverified(String reason) {
            return new RelationCheck(false, reason);
        }
    }
}
