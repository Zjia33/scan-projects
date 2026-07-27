package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
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
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class CodeGraphIntegrationService {
    private final CodeGraphProperties properties;
    private final CodeGraphClient client;
    private final CodeGraphResultMapper resultMapper;
    private final Set<UUID> preparedTasks = ConcurrentHashMap.newKeySet();

    public boolean prepare(UUID taskId, Path projectRoot) {
        if (!properties.enabled()) return false;
        try {
            client.prepare(taskId, projectRoot);
            preparedTasks.add(taskId);
            log.info("任务 {} CodeGraph 索引已就绪，模式={}", taskId, properties.getMode());
            return true;
        } catch (RuntimeException exception) {
            preparedTasks.remove(taskId);
            safeClientRelease(taskId);
            log.warn("任务 {} CodeGraph 初始化失败，继续使用内置语义分析：{}", taskId, exception.getMessage());
            return false;
        }
    }

    public ImpactDecision decideImpact(UUID taskId, List<CodeChunk> chunks,
                                       Set<Long> changedChunkIds, Set<Long> nativeImpactedChunkIds) {
        Set<Long> nativeIds = new LinkedHashSet<>(nativeImpactedChunkIds);
        if (!preparedTasks.contains(taskId) || changedChunkIds.isEmpty()) {
            return new ImpactDecision(Set.copyOf(nativeIds), Set.of(), 0, 0, properties.getMode());
        }

        List<CodeGraphClient.CodeGraphLocation> locations = new ArrayList<>();
        int failedQueries = 0;
        Map<Long, CodeChunk> byId = new LinkedHashMap<>();
        chunks.stream().filter(chunk -> chunk.getId() != null).forEach(chunk -> byId.put(chunk.getId(), chunk));
        Set<String> queriedSymbols = new LinkedHashSet<>();
        for (Long chunkId : changedChunkIds) {
            CodeChunk chunk = byId.get(chunkId);
            if (chunk == null || !"JAVA_METHOD".equals(chunk.getChunkType())) continue;
            String symbol = codeGraphSymbol(chunk.getSymbolName());
            if (symbol.isBlank() || !queriedSymbols.add(symbol)) continue;
            try {
                locations.addAll(client.impact(taskId, symbol, properties.getImpactDepth()));
            } catch (RuntimeException exception) {
                failedQueries++;
                log.warn("任务 {} CodeGraph impact 查询失败，symbol={}：{}",
                        taskId, symbol, exception.getMessage());
            }
        }

        CodeGraphResultMapper.MappingResult mapping = resultMapper.map(chunks, locations);
        Set<Long> externalIds = new LinkedHashSet<>(mapping.chunkIds());
        externalIds.removeAll(changedChunkIds);
        Set<Long> intersection = new LinkedHashSet<>(nativeIds);
        intersection.retainAll(externalIds);
        Set<Long> externalOnly = new LinkedHashSet<>(externalIds);
        externalOnly.removeAll(nativeIds);

        Set<Long> effective = new LinkedHashSet<>(nativeIds);
        if (properties.augmentsResults()) effective.addAll(externalIds);
        log.info("任务 {} CodeGraph 影响范围对比：mode={}，native={}，codegraph={}，intersection={}，"
                        + "codegraphOnly={}，unmapped={}，failedQueries={}",
                taskId, properties.getMode(), nativeIds.size(), externalIds.size(), intersection.size(),
                externalOnly.size(), mapping.unmappedLocations(), failedQueries);
        return new ImpactDecision(Set.copyOf(effective), Set.copyOf(externalIds),
                mapping.unmappedLocations(), failedQueries, properties.getMode());
    }

    public CandidateContext candidateContext(UUID taskId, CodeChunk current,
                                             List<CodeChunk> chunks, int requestedLimit) {
        if (!properties.augmentsResults() || !preparedTasks.contains(taskId)
                || current == null || !"JAVA_METHOD".equals(current.getChunkType())) {
            return CandidateContext.empty();
        }
        int limit = Math.max(1, Math.min(requestedLimit <= 0
                ? properties.getAgentContextLimit() : requestedLimit, properties.getAgentContextLimit()));
        String symbol = codeGraphSymbol(current.getSymbolName());
        if (symbol.isBlank()) return CandidateContext.empty();
        try {
            CodeGraphClient.RelatedLocations related = client.related(taskId, symbol, limit);
            List<CodeGraphClient.CodeGraphLocation> locations = new ArrayList<>();
            locations.addAll(related.callers());
            locations.addAll(related.callees());
            CodeGraphResultMapper.MappingResult mapping = resultMapper.map(chunks, locations);
            Set<Long> ids = new LinkedHashSet<>(mapping.chunkIds());
            ids.remove(current.getId());
            if (ids.isEmpty()) return CandidateContext.empty();

            Map<Long, CodeChunk> byId = new LinkedHashMap<>();
            chunks.stream().filter(chunk -> chunk.getId() != null).forEach(chunk -> byId.put(chunk.getId(), chunk));
            List<CodeChunk> selected = ids.stream().map(byId::get).filter(java.util.Objects::nonNull)
                    .sorted(Comparator.comparing(CodeChunk::getFilePath).thenComparingInt(CodeChunk::getStartLine))
                    .limit(limit).toList();
            Set<Long> selectedIds = selected.stream().map(CodeChunk::getId)
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            String text = "[CODEGRAPH_CANDIDATE] 以下调用关系只用于补充上下文；引用为漏洞证据前必须调用 "
                    + "verify_relation 验证。\n" + selected.stream()
                    .map(chunk -> "CHUNK_ID=" + chunk.getId() + " | " + chunk.getFilePath() + ":"
                            + chunk.getStartLine() + " | " + chunk.getSymbolName())
                    .collect(java.util.stream.Collectors.joining("\n"));
            return new CandidateContext(text, Set.copyOf(selectedIds), mapping.unmappedLocations());
        } catch (RuntimeException exception) {
            log.warn("任务 {} CodeGraph Agent 上下文查询失败，symbol={}：{}",
                    taskId, symbol, exception.getMessage());
            return CandidateContext.empty();
        }
    }

    public void release(UUID taskId) {
        preparedTasks.remove(taskId);
        safeClientRelease(taskId);
    }

    private void safeClientRelease(UUID taskId) {
        try {
            client.release(taskId);
        } catch (RuntimeException exception) {
            log.warn("任务 {} 释放 CodeGraph 状态失败：{}", taskId, exception.getMessage());
        }
    }

    private String codeGraphSymbol(String value) {
        if (value == null) return "";
        String symbol = value.strip();
        int parameters = symbol.indexOf('(');
        if (parameters >= 0) symbol = symbol.substring(0, parameters);
        return symbol.replace('#', '.');
    }

    public record ImpactDecision(Set<Long> effectiveImpactedChunkIds,
                                 Set<Long> codeGraphImpactedChunkIds,
                                 int unmappedLocations, int failedQueries,
                                 CodeGraphMode mode) {
    }

    public record CandidateContext(String text, Set<Long> candidateChunkIds, int unmappedLocations) {
        public CandidateContext {
            text = text == null ? "" : text;
            candidateChunkIds = candidateChunkIds == null ? Set.of() : Set.copyOf(candidateChunkIds);
        }

        public static CandidateContext empty() {
            return new CandidateContext("", Set.of(), 0);
        }
    }
}
