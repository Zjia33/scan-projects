package com.deepaudit.agent;

import java.util.Set;

/** Agent 只读工具的统一返回协议。 */
public record ToolResult(Status status, String code, String text,
                         Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds,
                         boolean truncated, String nextCursor) {
    public enum Status {
        OK, EMPTY, INVALID, DENIED, ERROR
    }

    public ToolResult(String text, Set<Long> evidenceChunkIds) {
        this(Status.OK, "OK", text, evidenceChunkIds, Set.of(), false, null);
    }

    public ToolResult(String text, Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds) {
        this(Status.OK, "OK", text, evidenceChunkIds, candidateChunkIds, false, null);
    }

    public ToolResult(Status status, String text, Set<Long> evidenceChunkIds,
                      Set<Long> candidateChunkIds) {
        this(status, status == null ? "OK" : status.name(), text,
                evidenceChunkIds, candidateChunkIds, false, null);
    }

    public ToolResult(Status status, String text, Set<Long> evidenceChunkIds,
                      Set<Long> candidateChunkIds, boolean truncated, String nextCursor) {
        this(status, status == null ? "OK" : status.name(), text,
                evidenceChunkIds, candidateChunkIds, truncated, nextCursor);
    }

    public ToolResult {
        status = status == null ? Status.OK : status;
        code = code == null || code.isBlank() ? status.name() : code;
        text = text == null || text.isBlank() ? "工具未返回结果" : text;
        if (text.length() > 12_000) {
            text = text.substring(0, 12_000);
            truncated = true;
        }
        evidenceChunkIds = evidenceChunkIds == null ? Set.of() : Set.copyOf(evidenceChunkIds);
        candidateChunkIds = candidateChunkIds == null ? Set.of() : Set.copyOf(candidateChunkIds);
        nextCursor = nextCursor == null || nextCursor.isBlank() ? null : nextCursor;
    }

    public String observationText() {
        return "[TOOL_RESULT status=" + status + " code=" + code + " truncated=" + truncated
                + " nextCursor=" + (nextCursor == null ? "-" : nextCursor) + "]\n" + text;
    }

    static ToolResult empty(String text) {
        return new ToolResult(Status.EMPTY, "NO_RESULTS", text, Set.of(), Set.of(), false, null);
    }

    static ToolResult invalid(String text) {
        return new ToolResult(Status.INVALID, "INVALID_ARGUMENT", text, Set.of(), Set.of(), false, null);
    }

    static ToolResult notFound(String text) {
        return new ToolResult(Status.ERROR, "NOT_FOUND", text, Set.of(), Set.of(), false, null);
    }

    static ToolResult forbidden(String text) {
        return new ToolResult(Status.DENIED, "ACCESS_DENIED", text, Set.of(), Set.of(), false, null);
    }

}
