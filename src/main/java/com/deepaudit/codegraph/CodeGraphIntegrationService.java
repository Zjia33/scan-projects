package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

// 负责 Base/Target CodeGraph 索引、增量影响范围和任务级作用域拓扑。
@Slf4j
@Service
@RequiredArgsConstructor
public class CodeGraphIntegrationService {
    private final CodeGraphProperties properties;
    private final CodeGraphClient client;
    private final CodeGraphResultMapper resultMapper;
    private final Map<UUID, Set<CodeGraphSnapshot>> preparedSnapshots = new ConcurrentHashMap<>();

    // 增量任务必须分别建立 Comparison Base 和 Target 索引。
    public boolean prepare(UUID taskId, Path baseRoot, Path targetRoot) {
        if (!properties.enabled()) return false;
        boolean base = prepareSnapshot(taskId, CodeGraphSnapshot.BASE, baseRoot);
        boolean target = prepareSnapshot(taskId, CodeGraphSnapshot.TARGET, targetRoot);
        return base && target;
    }

    private boolean prepareSnapshot(UUID taskId, CodeGraphSnapshot snapshot, Path root) {
        if (!properties.enabled()) return false;
        if (prepared(taskId, snapshot)) {
            log.debug("任务 {} CodeGraph {} 索引已绑定，跳过重复准备", taskId, snapshot);
            return true;
        }
        TimingDetailLog.info("任务 {} 开始准备 CodeGraph {} 索引：workspace={}",
                taskId, snapshot, root == null ? "-" : root.getFileName());
        try {
            client.prepare(taskId, snapshot, root);
            preparedSnapshots.computeIfAbsent(taskId,
                    ignored -> ConcurrentHashMap.newKeySet()).add(snapshot);
            TimingDetailLog.info("任务 {} CodeGraph {} 索引已就绪", taskId, snapshot);
            return true;
        } catch (RuntimeException exception) {
            preparedSnapshots.computeIfPresent(taskId, (ignored, values) -> {
                values.remove(snapshot);
                return values.isEmpty() ? null : values;
            });
            safeClientRelease(taskId);
            throw new CodeGraphException("CodeGraph " + snapshot + " 索引建立失败，无法保证增量覆盖: "
                    + exception.getMessage(), exception);
        }
    }

    // Target 查询当前变化影响，Base 查询删除和签名变化的历史调用者。
    public ImpactDecision decideImpact(UUID taskId, List<CodeChunk> chunks,
                                       Set<Long> changedChunkIds, Set<Long> contextualImpactedChunkIds,
                                       List<SemanticMethodChange> methodChanges) {
        Set<Long> contextualIds = new LinkedHashSet<>(contextualImpactedChunkIds);
        if (!prepared(taskId, CodeGraphSnapshot.TARGET)) {
            return new ImpactDecision(Set.copyOf(contextualIds), Set.of(), List.of(), 0, 0);
        }

        List<CodeGraphClient.CodeGraphLocation> locations = new ArrayList<>();
        int[] failedQueries = {0};
        Map<Long, CodeChunk> byId = chunks.stream().filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, chunk -> chunk,
                        (left, right) -> left, LinkedHashMap::new));
        Set<String> queried = new LinkedHashSet<>();

        for (Long chunkId : changedChunkIds) {
            CodeChunk chunk = byId.get(chunkId);
            if (chunk == null || !"JAVA_METHOD".equals(chunk.getChunkType())) continue;
            queryImpact(taskId, CodeGraphSnapshot.TARGET, codeGraphSymbol(chunk.getSymbolName()),
                    queried, locations, failedQueries);
        }

        for (SemanticMethodChange change : methodChanges) {
            if (change.getChangeKind() == SemanticChangeKind.METHOD_DELETED
                    || change.getChangeKind() == SemanticChangeKind.SIGNATURE_CHANGED) {
                String baseSymbol = codeGraphSymbol(change.getBaseSymbol());
                queryImpact(taskId, CodeGraphSnapshot.BASE, baseSymbol, queried, locations, failedQueries);
                queryBaseCallers(taskId, baseSymbol, queried, locations, failedQueries);
            }
            if (change.getChangeKind() == SemanticChangeKind.SIGNATURE_CHANGED) {
                queryImpact(taskId, CodeGraphSnapshot.TARGET, codeGraphSymbol(change.getTargetSymbol()),
                        queried, locations, failedQueries);
            }
        }

        if (failedQueries[0] > 0) {
            throw new CodeGraphException("CodeGraph 有 " + failedQueries[0]
                    + " 个增量影响查询失败，不能将失败解释为无影响");
        }

        return mapImpact(taskId, chunks, changedChunkIds, contextualIds, locations,
                queried.size(), failedQueries[0]);
    }

    public ImpactDecision mapImpact(UUID taskId, List<CodeChunk> chunks, Set<Long> changedChunkIds,
                                    Set<Long> contextualImpactedChunkIds,
                                    List<CodeGraphClient.CodeGraphLocation> locations) {
        return mapImpact(taskId, chunks, changedChunkIds, contextualImpactedChunkIds,
                locations, 0, 0);
    }

    private ImpactDecision mapImpact(UUID taskId, List<CodeChunk> chunks, Set<Long> changedChunkIds,
                                     Set<Long> contextualImpactedChunkIds,
                                     List<CodeGraphClient.CodeGraphLocation> locations,
                                     int queryCount, int failedQueries) {
        CodeGraphResultMapper.MappingResult mapping = resultMapper.map(chunks, locations);
        Set<Long> codeGraphIds = new LinkedHashSet<>(mapping.chunkIds());
        codeGraphIds.removeAll(changedChunkIds);
        Set<Long> effective = new LinkedHashSet<>(contextualImpactedChunkIds);
        effective.addAll(codeGraphIds);

        TimingDetailLog.info("任务 {} CodeGraph 影响映射完成：context={}，codegraph={}，queries={}，"
                        + "locations={}，unmapped={}，failed={}",
                taskId, contextualImpactedChunkIds.size(), codeGraphIds.size(), queryCount,
                locations.size(), mapping.unmappedLocations(), failedQueries);
        return new ImpactDecision(Set.copyOf(effective), Set.copyOf(codeGraphIds), List.copyOf(locations),
                mapping.unmappedLocations(), failedQueries);
    }

    private void queryImpact(UUID taskId, CodeGraphSnapshot snapshot, String symbol,
                             Set<String> queried, List<CodeGraphClient.CodeGraphLocation> locations,
                             int[] failedQueries) {
        if (symbol.isBlank() || !prepared(taskId, snapshot)
                || !queried.add(snapshot + ":impact:" + symbol)) return;
        try {
            locations.addAll(client.impact(taskId, snapshot, symbol, properties.getImpactDepth()));
        } catch (RuntimeException exception) {
            failedQueries[0]++;
            log.warn("任务 {} CodeGraph {} impact 查询失败，symbol={}：{}",
                    taskId, snapshot, symbol, exception.getMessage());
        }
    }

    private void queryBaseCallers(UUID taskId, String symbol, Set<String> queried,
                                  List<CodeGraphClient.CodeGraphLocation> locations, int[] failedQueries) {
        if (symbol.isBlank() || !prepared(taskId, CodeGraphSnapshot.BASE)
                || !queried.add(CodeGraphSnapshot.BASE + ":callers:" + symbol)) return;
        try {
            locations.addAll(client.related(taskId, CodeGraphSnapshot.BASE, symbol,
                    safeRelationLimit()).callers());
        } catch (RuntimeException exception) {
            failedQueries[0]++;
            log.warn("任务 {} CodeGraph BASE callers 查询失败，symbol={}：{}",
                    taskId, symbol, exception.getMessage());
        }
    }

    // 查询作用域内的直接 callers/callees，形成跨方法分析的权威拓扑输入。
    public ScopedTopology scopedTopology(UUID taskId, List<CodeChunk> chunks, Set<Long> primaryScopeIds) {
        if (!prepared(taskId, CodeGraphSnapshot.TARGET) || primaryScopeIds.isEmpty()) {
            return ScopedTopology.empty();
        }
        Map<Long, CodeChunk> byId = chunks.stream().filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, chunk -> chunk,
                        (left, right) -> left, LinkedHashMap::new));
        Map<String, ScopedRelation> relations = new LinkedHashMap<>();
        Set<Long> contextIds = new LinkedHashSet<>();
        List<CodeGraphClient.CodeGraphLocation> locations = new ArrayList<>();
        int unmapped = 0;
        int failed = 0;
        Set<String> queried = new LinkedHashSet<>();

        for (Long id : primaryScopeIds) {
            CodeChunk current = byId.get(id);
            if (current == null || !"JAVA_METHOD".equals(current.getChunkType())) continue;
            String symbol = codeGraphSymbol(current.getSymbolName());
            if (symbol.isBlank() || !queried.add(symbol)) continue;
            try {
                CodeGraphClient.RelatedLocations related = client.related(taskId, CodeGraphSnapshot.TARGET,
                        symbol, safeRelationLimit());
                for (CodeGraphClient.CodeGraphLocation callerLocation : related.callers()) {
                    locations.add(callerLocation);
                    CodeChunk caller = resultMapper.mapLocation(chunks, callerLocation);
                    if (caller == null || caller.getId() == null || caller.getId().equals(id)) {
                        unmapped++;
                        continue;
                    }
                    contextIds.add(caller.getId());
                    addRelation(relations, caller, current, "CODEGRAPH_CALLER");
                }
                for (CodeGraphClient.CodeGraphLocation calleeLocation : related.callees()) {
                    locations.add(calleeLocation);
                    CodeChunk callee = resultMapper.mapLocation(chunks, calleeLocation);
                    if (callee == null || callee.getId() == null || callee.getId().equals(id)) {
                        unmapped++;
                        continue;
                    }
                    contextIds.add(callee.getId());
                    addRelation(relations, current, callee, "CODEGRAPH_CALLEE");
                }
            } catch (RuntimeException exception) {
                failed++;
                log.warn("任务 {} CodeGraph 作用域关系查询失败，symbol={}：{}",
                        taskId, symbol, exception.getMessage());
            }
        }
        contextIds.removeAll(primaryScopeIds);
        if (failed > 0) {
            throw new CodeGraphException("CodeGraph 有 " + failed + " 个作用域关系查询失败");
        }
        return new ScopedTopology(List.copyOf(relations.values()), Set.copyOf(contextIds),
                List.copyOf(locations), unmapped, failed);
    }

    private void addRelation(Map<String, ScopedRelation> relations, CodeChunk caller, CodeChunk callee,
                             String reason) {
        String key = caller.getId() + "->" + callee.getId();
        relations.putIfAbsent(key, new ScopedRelation(caller.getId(), callee.getId(),
                simpleSymbol(callee.getSymbolName()), reason));
    }

    public RelationContext relationContext(UUID taskId, CodeChunk current,
                                           List<CodeChunk> chunks, int requestedLimit) {
        if (!prepared(taskId, CodeGraphSnapshot.TARGET)
                || current == null || !"JAVA_METHOD".equals(current.getChunkType())) {
            return RelationContext.empty();
        }
        int limit = Math.max(1, Math.min(requestedLimit <= 0
                ? properties.getAgentContextLimit() : requestedLimit, properties.getAgentContextLimit()));
        String symbol = codeGraphSymbol(current.getSymbolName());
        if (symbol.isBlank()) return RelationContext.empty();
        try {
            CodeGraphClient.RelatedLocations related = client.related(taskId, CodeGraphSnapshot.TARGET,
                    symbol, limit);
            List<CodeGraphClient.CodeGraphLocation> locations = new ArrayList<>();
            locations.addAll(related.callers());
            locations.addAll(related.callees());
            CodeGraphResultMapper.MappingResult mapping = resultMapper.map(chunks, locations);
            Set<Long> ids = new LinkedHashSet<>(mapping.chunkIds());
            ids.remove(current.getId());
            if (ids.isEmpty()) return RelationContext.empty();

            Map<Long, CodeChunk> byId = chunks.stream().filter(chunk -> chunk.getId() != null)
                    .collect(Collectors.toMap(CodeChunk::getId, chunk -> chunk,
                            (left, right) -> left, LinkedHashMap::new));
            List<CodeChunk> selected = ids.stream().map(byId::get).filter(Objects::nonNull)
                    .sorted(Comparator.comparing(CodeChunk::getFilePath).thenComparingInt(CodeChunk::getStartLine))
                    .limit(limit).toList();
            Set<Long> selectedIds = selected.stream().map(CodeChunk::getId)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            String text = "[VERIFIED_EVIDENCE][CODEGRAPH_RELATIONS] CodeGraph Target 索引确认以下方法与当前方法存在直接调用关系。\n"
                    + selected.stream()
                    .map(chunk -> "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":"
                            + chunk.getStartLine() + " | " + chunk.getSymbolName())
                    .collect(Collectors.joining("\n"));
            return new RelationContext(text, Set.copyOf(selectedIds), mapping.unmappedLocations());
        } catch (RuntimeException exception) {
            log.warn("任务 {} CodeGraph Agent 上下文查询失败，symbol={}：{}",
                    taskId, symbol, exception.getMessage());
            return RelationContext.empty();
        }
    }

    // 使用 CodeGraph 对其它搜索工具发现的候选执行直接关系验证。
    public RelationCheck verifyDirectRelation(UUID taskId, CodeChunk current, CodeChunk candidate,
                                              List<CodeChunk> chunks) {
        if (!prepared(taskId, CodeGraphSnapshot.TARGET) || current == null || candidate == null
                || !"JAVA_METHOD".equals(current.getChunkType())
                || !"JAVA_METHOD".equals(candidate.getChunkType())) {
            return RelationCheck.unverified("CodeGraph Target 索引未就绪或待验证对象不是 Java 方法");
        }
        String symbol = codeGraphSymbol(current.getSymbolName());
        if (symbol.isBlank()) return RelationCheck.unverified("当前代码块没有可查询的 CodeGraph 符号");
        try {
            CodeGraphClient.RelatedLocations related = client.related(
                    taskId, CodeGraphSnapshot.TARGET, symbol, safeRelationLimit());
            List<CodeGraphClient.CodeGraphLocation> locations = new ArrayList<>();
            locations.addAll(related.callers());
            locations.addAll(related.callees());
            Set<Long> mapped = new LinkedHashSet<>(resultMapper.map(chunks, locations).chunkIds());
            boolean verified = candidate.getId() != null && mapped.contains(candidate.getId());
            if (verified) {
                TimingDetailLog.info("任务 {} CodeGraph 直接关系复验通过：{} <-> {}",
                        taskId, current.getId(), candidate.getId());
                return new RelationCheck(true, "CodeGraph Target 索引确认两个方法存在直接调用关系");
            }
            TimingDetailLog.info("任务 {} CodeGraph 直接关系复验未命中：{} <-> {}，mapped={}",
                    taskId, current.getId(), candidate.getId(), mapped.size());
            return RelationCheck.unverified("CodeGraph 未确认当前方法与待验证方法存在直接调用关系");
        } catch (RuntimeException exception) {
            log.warn("任务 {} CodeGraph 直接关系复验失败：{} <-> {}，原因={}",
                    taskId, current.getId(), candidate.getId(), exception.getMessage());
            return RelationCheck.unverified("CodeGraph 关系验证失败，可继续检查其它确定性关系");
        }
    }

    public void release(UUID taskId) {
        boolean prepared = preparedSnapshots.remove(taskId) != null;
        safeClientRelease(taskId);
        if (prepared) TimingDetailLog.info("任务 {} CodeGraph Base/Target 任务状态已释放", taskId);
    }

    private boolean prepared(UUID taskId, CodeGraphSnapshot snapshot) {
        return preparedSnapshots.getOrDefault(taskId, Set.of()).contains(snapshot);
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

    private String simpleSymbol(String value) {
        String symbol = codeGraphSymbol(value);
        int separator = symbol.lastIndexOf('.');
        return separator < 0 ? symbol : symbol.substring(separator + 1);
    }

    public record ImpactDecision(Set<Long> effectiveImpactedChunkIds,
                                 Set<Long> codeGraphImpactedChunkIds,
                                 List<CodeGraphClient.CodeGraphLocation> locations,
                                 int unmappedLocations, int failedQueries) {
    }

    public record ScopedRelation(Long callerChunkId, Long calleeChunkId, String calledName, String source) {
    }

    public record ScopedTopology(List<ScopedRelation> relations, Set<Long> contextChunkIds,
                                 List<CodeGraphClient.CodeGraphLocation> locations,
                                 int unmappedLocations, int failedQueries) {
        public ScopedTopology {
            relations = relations == null ? List.of() : List.copyOf(relations);
            contextChunkIds = contextChunkIds == null ? Set.of() : Set.copyOf(contextChunkIds);
            locations = locations == null ? List.of() : List.copyOf(locations);
        }

        public static ScopedTopology empty() {
            return new ScopedTopology(List.of(), Set.of(), List.of(), 0, 0);
        }
    }

    public record RelationContext(String text, Set<Long> relatedChunkIds, int unmappedLocations) {
        public RelationContext {
            text = text == null ? "" : text;
            relatedChunkIds = relatedChunkIds == null ? Set.of() : Set.copyOf(relatedChunkIds);
        }

        public static RelationContext empty() {
            return new RelationContext("", Set.of(), 0);
        }
    }

    public record RelationCheck(boolean verified, String reason) {
        private static RelationCheck unverified(String reason) {
            return new RelationCheck(false, reason);
        }
    }
}
