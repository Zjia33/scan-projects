package com.deepaudit.rag;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.mapper.CodeChunkMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RagService {

    private final CodeChunkMapper chunkMapper;
    private final EmbeddingService embeddingService;
    private final VectorRecallStore vectorRecallStore;

    public List<CodeChunk> retrieve(UUID taskId, String query, int limit) {
        return retrieve(chunkMapper.findByTaskId(taskId), query, limit);
    }

    public List<CodeChunk> retrieve(List<CodeChunk> chunks, String query, int limit) {
        UUID taskId = chunks.stream().map(CodeChunk::getTaskId).filter(java.util.Objects::nonNull)
                .findFirst().orElse(null);
        return retrieveDetailed(chunks, new RetrievalRequest(taskId, null, query, null, null, Set.of(), limit))
                .stream().map(RetrievedCode::chunk).toList();
    }

    // 先由向量存储召回近邻，再用关键词和确定性结构关系重排候选代码块。
    public List<RetrievedCode> retrieveDetailed(List<CodeChunk> chunks, RetrievalRequest request) {
        if (request.query() == null || request.query().isBlank() || chunks.isEmpty()) return List.of();
        int limit = Math.max(1, Math.min(request.limit(), 20));
        double[] queryVector = embeddingService.embed(request.query());
        Set<String> keywords = tokenize(request.query());
        UUID taskId = request.taskId() != null ? request.taskId() : chunks.get(0).getTaskId();
        int vectorCandidateLimit = Math.min(200, Math.max(40, limit * 8));
        List<VectorRecallStore.VectorMatch> vectorMatches = vectorRecallStore.search(
                chunks, taskId, request.currentChunkId(), queryVector, vectorCandidateLimit);
        Map<Long, Double> vectorScores = vectorMatches.stream().collect(Collectors.toMap(
                VectorRecallStore.VectorMatch::chunkId,
                VectorRecallStore.VectorMatch::cosineSimilarity,
                Math::max, LinkedHashMap::new));

        Map<Long, CodeChunk> chunksById = chunks.stream()
                .filter(chunk -> chunk.getId() != null)
                .collect(Collectors.toMap(CodeChunk::getId, chunk -> chunk,
                        (left, right) -> left, LinkedHashMap::new));
        Map<Long, CodeChunk> candidates = new LinkedHashMap<>();
        vectorMatches.forEach(match -> {
            CodeChunk chunk = chunksById.get(match.chunkId());
            if (chunk != null) candidates.putIfAbsent(chunk.getId(), chunk);
        });
        // 向量近邻之外补入同文件、同接口和精确符号关系，避免 ANN 过滤丢失确定性上下文。
        chunks.stream()
                .filter(chunk -> chunk.getId() != null)
                .filter(chunk -> request.currentChunkId() == null || !request.currentChunkId().equals(chunk.getId()))
                .filter(chunk -> hasStructuralRelation(chunk, request))
                .forEach(chunk -> candidates.putIfAbsent(chunk.getId(), chunk));

        return candidates.values().stream()
                .map(chunk -> score(chunk, request, vectorScores.getOrDefault(chunk.getId(), 0.0), keywords))
                .filter(scored -> scored.score() >= 0.03)
                .sorted(Comparator.comparingDouble(RetrievedCode::score).reversed())
                .limit(limit)
                .collect(Collectors.toList());
    }

    // 以结构关系为主计算候选分数，同时记录可解释的命中原因。
    private RetrievedCode score(CodeChunk chunk, RetrievalRequest request,
                                double cosine, Set<String> keywords) {
        String haystack = searchableText(chunk);
        long matches = keywords.stream().filter(word -> haystack.contains(word)).count();
        double lexical = keywords.isEmpty() ? 0
                : Math.min((double) matches / Math.min(6, keywords.size()), 1.0);
        double relation = 0;
        List<String> reasons = new ArrayList<>();
        if (request.currentFile() != null && request.currentFile().equals(chunk.getFilePath())) {
            relation += 0.35;
            reasons.add("同一文件");
        }
        if (request.endpoint() != null && request.endpoint().equals(chunk.getEndpoint())) {
            relation += 0.25;
            reasons.add("同一接口");
        }
        for (String symbol : request.symbols()) {
            if (!symbol.isBlank() && haystack.contains(symbol.toLowerCase(Locale.ROOT))) {
                relation += 0.15;
                reasons.add("符号匹配:" + symbol);
            }
        }
        relation = Math.min(relation, 1.0);
        // 向量只负责发现候选。代码审计更依赖符号和结构关系，不能让“语义相似”主导排序。
        double finalScore = Math.max(0, cosine) * 0.10 + lexical * 0.25 + relation * 0.65;
        if (matches > 0) reasons.add("关键词匹配:" + matches);
        if (cosine > 0) reasons.add("语义相似");
        return new RetrievedCode(chunk, finalScore,
                "RAG候选（仅用于发现，不是漏洞证据）："
                        + (reasons.isEmpty() ? "向量相似" : String.join("、", new LinkedHashSet<>(reasons))));
    }

    private boolean hasStructuralRelation(CodeChunk chunk, RetrievalRequest request) {
        if (request.currentFile() != null && request.currentFile().equals(chunk.getFilePath())) return true;
        if (request.endpoint() != null && request.endpoint().equals(chunk.getEndpoint())) return true;
        String haystack = searchableText(chunk);
        return request.symbols().stream()
                .anyMatch(symbol -> !symbol.isBlank() && haystack.contains(symbol.toLowerCase(Locale.ROOT)));
    }

    private String searchableText(CodeChunk chunk) {
        return (chunk.getFilePath() + " " + chunk.getSymbolName() + " " + chunk.getEndpoint()
                + " " + chunk.getParameters() + " " + chunk.getAnnotations() + " "
                + chunk.getCalledSymbols() + " " + chunk.getContent()).toLowerCase(Locale.ROOT);
    }

    // 拆分驼峰和非字母数字边界，形成去重的词法检索集合。
    private Set<String> tokenize(String value) {
        String expanded = value.replaceAll("([a-z])([A-Z])", "$1 $2").toLowerCase(Locale.ROOT);
        return java.util.Arrays.stream(expanded.split("[^\\p{L}\\p{N}_$]+"))
                .filter(token -> token.length() > 1)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public record RetrievalRequest(UUID taskId, Long currentChunkId, String query,
                                   String endpoint, String currentFile, Set<String> symbols, int limit) {
        public RetrievalRequest {
            symbols = symbols == null ? Set.of() : Set.copyOf(symbols);
        }
    }

    public record RetrievedCode(CodeChunk chunk, double score, String reason) {
    }
}
