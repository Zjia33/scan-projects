package com.deepaudit.agent;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** Agent 只读工具的统一返回协议。 */
public record ToolResult(Status status, String code, String text,
                         Set<Long> evidenceChunkIds, Set<Long> candidateChunkIds,
                         boolean truncated, String nextCursor) {
    static final int MAX_TEXT_CHARS = 24_000;

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
        if (text.length() > MAX_TEXT_CHARS) {
            int originalChars = text.length();
            text = limitWithMarker(text, MAX_TEXT_CHARS,
                    "[TOOL_RESULT_TRUNCATED originalChars=" + originalChars
                            + " retainedChars=" + MAX_TEXT_CHARS
                            + " action=refine_query_or_use_cursor]");
            truncated = true;
        }
        evidenceChunkIds = immutableOrderedSet(evidenceChunkIds);
        candidateChunkIds = immutableOrderedSet(candidateChunkIds);
        nextCursor = nextCursor == null || nextCursor.isBlank() ? null : nextCursor;
    }

    public String observationText() {
        return "[TOOL_RESULT status=" + status + " code=" + code + " truncated=" + truncated
                + " nextCursor=" + (nextCursor == null ? "-" : nextCursor)
                + " evidenceChunkIds=" + evidenceChunkIds
                + " candidateChunkIds=" + candidateChunkIds
                + " textChars=" + text.length() + "]\n" + text;
    }

    private static String limitWithMarker(String value, int maxChars, String markerText) {
        String marker = "\n... " + markerText + " ...\n";
        int available = Math.max(0, maxChars - marker.length());
        int headChars = available * 2 / 3;
        int tailChars = available - headChars;
        int headEnd = lineBoundaryBefore(value, headChars);
        int tailStart = lineBoundaryAfter(value, value.length() - tailChars);
        return value.substring(0, headEnd).stripTrailing() + marker
                + value.substring(tailStart).stripLeading();
    }

    private static int lineBoundaryBefore(String value, int target) {
        int boundary = value.lastIndexOf('\n', Math.min(target, value.length()));
        return boundary < 0 ? Math.min(target, value.length()) : boundary;
    }

    private static int lineBoundaryAfter(String value, int target) {
        int safeTarget = Math.max(0, Math.min(target, value.length()));
        int boundary = value.indexOf('\n', safeTarget);
        return boundary < 0 ? safeTarget : Math.min(value.length(), boundary + 1);
    }

    private static Set<Long> immutableOrderedSet(Set<Long> values) {
        if (values == null || values.isEmpty()) return Set.of();
        return Collections.unmodifiableSet(new LinkedHashSet<>(values));
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
