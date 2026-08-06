package com.deepaudit.agent;

import java.util.Set;

/** Agent 只读工具的统一返回协议。 */
public record ToolResult(Status status, String code, String text,
                         Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds,
                         boolean truncated) {
    public enum Status {
        OK, EMPTY, INVALID, DENIED, ERROR
    }

    public ToolResult(String text, Set<Long> evidenceChunkIds) {
        this(Status.OK, "OK", text, evidenceChunkIds, Set.of(), false);
    }

    public ToolResult(String text, Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds) {
        this(Status.OK, "OK", text, evidenceChunkIds, candidateChunkIds, false);
    }

    public ToolResult(Status status, String text, Set<Long> evidenceChunkIds,
                      Set<Long> candidateChunkIds) {
        this(status, status == null ? "OK" : status.name(), text,
                evidenceChunkIds, candidateChunkIds, false);
    }

    public ToolResult(Status status, String code, String text,
                      Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds) {
        this(status, code, text, evidenceChunkIds, candidateChunkIds, false);
    }

    public ToolResult {
        status = status == null ? Status.OK : status;
        code = code == null || code.isBlank() ? status.name() : code;
        text = text == null || text.isBlank() ? "工具未返回结果" : text;
        if (text.length() > 12_000) {
            text = text.substring(0, 11_900)
                    + "\n[RESULT_LIMIT] 工具结果达到安全字符上限；未返回内容不代表不存在，请缩小查询范围。";
            truncated = true;
        }
        evidenceChunkIds = evidenceChunkIds == null ? Set.of() : Set.copyOf(evidenceChunkIds);
        candidateChunkIds = candidateChunkIds == null ? Set.of() : Set.copyOf(candidateChunkIds);
    }

    public String observationText() {
        return "[TOOL_RESULT status=" + status + " code=" + code + "]\n" + text;
    }

    static ToolResult empty(String text) {
        return new ToolResult(Status.EMPTY, "NO_RESULTS", text, Set.of(), Set.of(), false);
    }

    static ToolResult invalid(String text) {
        return new ToolResult(Status.INVALID, "INVALID_ARGUMENT", text, Set.of(), Set.of(), false);
    }

    static ToolResult notFound(String text) {
        return new ToolResult(Status.ERROR, "NOT_FOUND", text, Set.of(), Set.of(), false);
    }

    static ToolResult forbidden(String text) {
        return new ToolResult(Status.DENIED, "ACCESS_DENIED", text, Set.of(), Set.of(), false);
    }

}
