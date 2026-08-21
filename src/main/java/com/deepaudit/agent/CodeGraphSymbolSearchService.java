package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.codegraph.CodeGraphResultMapper;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.recon.ReconService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/** 使用完整 Target CodeGraph 索引补充符号候选，并按需物化可引用的任务代码块。 */
@Service
@RequiredArgsConstructor
public class CodeGraphSymbolSearchService {
    private static final int QUERY_LIMIT = 100;
    private static final Set<String> NODE_KINDS = Set.of(
            "file", "module", "class", "struct", "interface", "trait", "protocol",
            "function", "method", "property", "field", "variable", "constant", "enum",
            "enum_member", "type_alias", "namespace", "parameter", "import", "export",
            "route", "component");
    private final Object[] materializationLocks = locks();

    private final CodeGraphIntegrationService codeGraph;
    private final CodeGraphResultMapper resultMapper;
    private final ReconService reconService;
    private final CodeChunkMapper chunkMapper;

    public Expansion expand(UUID taskId, ToolArguments arguments, List<CodeChunk> sessionChunks) {
        String symbol = arguments.string("symbol");
        if (symbol.isBlank()) return Expansion.skipped();

        String codeGraphKind = codeGraphKind(arguments.string("kind"));
        String codeGraphSearch = codeGraphSearch(symbol);
        CodeGraphIntegrationService.SymbolQueryResult query = codeGraph.querySymbols(
                taskId, codeGraphSearch, codeGraphKind, QUERY_LIMIT);
        if (!query.attempted()) return Expansion.skipped();
        if (query.failed()) {
            return new Expansion(true, true,
                    "[CODEGRAPH_QUERY status=ERROR] 完整 Target 符号索引查询失败：" + safe(query.detail()));
        }

        List<com.deepaudit.codegraph.CodeGraphClient.CodeGraphLocation> locations = query.locations();
        CodeGraphResultMapper.MappingResult mapping = resultMapper.map(sessionChunks, locations);
        int materialized = 0;
        if (mapping.unmappedLocations() > 0 && query.targetRoot() != null) {
            synchronized (lock(taskId)) {
                materialized = reconService.materializeCodeGraphLocations(
                        taskId, query.targetRoot(), locations);
                List<CodeChunk> refreshed = chunkMapper.findByTaskId(taskId);
                if (refreshed != null && !refreshed.isEmpty()) {
                    sessionChunks.clear();
                    sessionChunks.addAll(refreshed);
                }
            }
            mapping = resultMapper.map(sessionChunks, locations);
        }

        boolean limitReached = locations.size() >= QUERY_LIMIT;
        String note = "[CODEGRAPH_QUERY status=OK] locations=" + locations.size()
                + " mappedChunkIds=" + mapping.chunkIds().size()
                + " materializedChunks=" + materialized
                + " unmappedLocations=" + mapping.unmappedLocations()
                + " queryLimitReached=" + limitReached
                + (limitReached ? "；结果可能不完整，请增加 symbol 限定" : "");
        return new Expansion(true, false, note);
    }

    private String codeGraphKind(String value) {
        if (value == null || value.isBlank()) return "";
        String normalized = value.strip().toLowerCase(Locale.ROOT);
        if (NODE_KINDS.contains(normalized)) return normalized;
        if (normalized.endsWith("_method") || normalized.contains("method")) return "method";
        if (normalized.endsWith("_class") || normalized.contains("class")) return "class";
        if (normalized.contains("interface")) return "interface";
        if (normalized.contains("function")) return "function";
        if (normalized.contains("field")) return "field";
        if (normalized.contains("property")) return "property";
        if (normalized.contains("constant")) return "constant";
        if (normalized.endsWith("_file") || normalized.equals("java_file")) return "file";
        return "";
    }

    private String codeGraphSearch(String value) {
        String search = value.strip();
        int parameters = search.indexOf('(');
        if (parameters >= 0) search = search.substring(0, parameters);
        return search.replace('#', '.');
    }

    private Object lock(UUID taskId) {
        return materializationLocks[Math.floorMod(taskId.hashCode(), materializationLocks.length)];
    }

    private static Object[] locks() {
        Object[] values = new Object[32];
        java.util.Arrays.setAll(values, ignored -> new Object());
        return values;
    }

    private String safe(String value) {
        if (value == null || value.isBlank()) return "未知错误";
        return value.substring(0, Math.min(value.length(), 500));
    }

    public record Expansion(boolean attempted, boolean failed, String note) {
        public Expansion {
            note = note == null ? "" : note;
        }

        static Expansion skipped() {
            return new Expansion(false, false, "");
        }

        ToolResult merge(ToolResult base) {
            if (!attempted) return base;
            String text = base.text() + "\n\n" + note;
            if (!failed) {
                return new ToolResult(base.status(), base.code(), text, base.evidenceChunkIds(),
                        base.candidateChunkIds(), base.truncated(), base.nextCursor());
            }
            if (base.status() == ToolResult.Status.EMPTY) {
                return new ToolResult(ToolResult.Status.ERROR, "CODEGRAPH_QUERY_FAILED", text,
                        base.evidenceChunkIds(), base.candidateChunkIds(), base.truncated(), base.nextCursor());
            }
            return new ToolResult(base.status(), "PARTIAL_RESULT", text, base.evidenceChunkIds(),
                    base.candidateChunkIds(), base.truncated(), base.nextCursor());
        }
    }
}
