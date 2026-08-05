package com.deepaudit.codegraph;

import com.deepaudit.domain.CodeChunk;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Component
public class CodeGraphResultMapper {
    // 执行 map 对应的数据库访问操作。
    public MappingResult map(List<CodeChunk> chunks, List<CodeGraphClient.CodeGraphLocation> locations) {
        Map<String, List<CodeChunk>> byPath = index(chunks);

        Set<Long> ids = new LinkedHashSet<>();
        int unmapped = 0;
        for (CodeGraphClient.CodeGraphLocation location : locations) {
            List<CodeChunk> candidates = candidates(byPath, location.filePath());
            CodeChunk match = select(candidates, location);
            if (match == null || match.getId() == null) unmapped++;
            else ids.add(match.getId());
        }
        return new MappingResult(Set.copyOf(ids), unmapped);
    }

    // 将单个 CodeGraph 位置严格映射到唯一代码块；歧义位置不会被猜测。
    public CodeChunk mapLocation(List<CodeChunk> chunks, CodeGraphClient.CodeGraphLocation location) {
        if (location == null) return null;
        Map<String, List<CodeChunk>> byPath = index(chunks);
        return select(candidates(byPath, location.filePath()), location);
    }

    private Map<String, List<CodeChunk>> index(List<CodeChunk> chunks) {
        Map<String, List<CodeChunk>> byPath = new LinkedHashMap<>();
        for (CodeChunk chunk : chunks) {
            byPath.computeIfAbsent(normalizePath(chunk.getFilePath()), ignored -> new ArrayList<>()).add(chunk);
        }
        byPath.values().forEach(values -> values.sort(Comparator.comparingInt(CodeChunk::getStartLine)));
        return byPath;
    }

    // 执行 candidates 对应的数据库访问操作。
    private List<CodeChunk> candidates(Map<String, List<CodeChunk>> byPath, String path) {
        String normalized = normalizePath(path);
        List<CodeChunk> exact = byPath.get(normalized);
        if (exact != null) return exact;
        List<List<CodeChunk>> pathMatches = byPath.entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(normalized)
                        || normalized.toLowerCase(Locale.ROOT)
                        .endsWith("/" + entry.getKey().toLowerCase(Locale.ROOT)))
                .map(Map.Entry::getValue).toList();
        return pathMatches.size() == 1 ? pathMatches.get(0) : List.of();
    }

    // 从数据库查询 select 对应的记录。
    private CodeChunk select(List<CodeChunk> candidates, CodeGraphClient.CodeGraphLocation location) {
        if (candidates.isEmpty()) return null;
        if (location.startLine() != null && location.startLine() > 0) {
            List<CodeChunk> atLine = candidates.stream()
                    .filter(chunk -> location.startLine() >= chunk.getStartLine()
                            && location.startLine() <= chunk.getEndLine()).toList();
            if (atLine.size() == 1) return atLine.get(0);
            CodeChunk named = named(atLine, location.name());
            if (named != null) return named;
        }
        CodeChunk named = named(candidates, location.name());
        return named != null ? named : candidates.size() == 1 ? candidates.get(0) : null;
    }

    // 执行 named 对应的数据库访问操作。
    private CodeChunk named(List<CodeChunk> candidates, String locationName) {
        String expected = simpleName(locationName);
        if (expected.isBlank()) return null;
        List<CodeChunk> matches = candidates.stream()
                .filter(chunk -> expected.equals(simpleName(chunk.getSymbolName()))).toList();
        return matches.size() == 1 ? matches.get(0) : null;
    }

    // 执行 simpleName 对应的数据库访问操作。
    private String simpleName(String value) {
        if (value == null) return "";
        String name = value.strip();
        int parentheses = name.indexOf('(');
        if (parentheses >= 0) name = name.substring(0, parentheses);
        int separator = Math.max(name.lastIndexOf('#'), Math.max(name.lastIndexOf('.'), name.lastIndexOf(':')));
        return (separator >= 0 ? name.substring(separator + 1) : name).toLowerCase(Locale.ROOT);
    }

    // 执行 normalizePath 对应的数据库访问操作。
    private String normalizePath(String value) {
        if (value == null) return "";
        String path = value.replace('\\', '/').strip();
        while (path.startsWith("./")) path = path.substring(2);
        return path;
    }

    public record MappingResult(Set<Long> chunkIds, int unmappedLocations) {
    }
}
