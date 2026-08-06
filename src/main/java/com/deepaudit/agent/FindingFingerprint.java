package com.deepaudit.agent;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Generates a stable identity for a Critic-confirmed vulnerability location.
 *
 * <p>The affected HTTP endpoint and the evidence-chain order are deliberately
 * excluded: both can differ when separate professional agents reach the same
 * sink through different callers.</p>
 */
public final class FindingFingerprint {

    private FindingFingerprint() {
    }

    public static String create(VulnerabilityType type, CodeChunk chunk, int startLine, int endLine) {
        if (chunk == null) throw new IllegalArgumentException("代码块不能为空");
        return create(type, chunk.getFilePath(), chunk.getSymbolName(),
                codeAnchor(chunk, startLine, endLine));
    }

    public static String create(VulnerabilityType type, String filePath, String symbolName,
                                String codeAnchor) {
        String normalized = String.join("|",
                type == null ? "" : type.name(),
                normalizePath(filePath),
                normalizeSymbol(symbolName),
                codeAnchor == null ? "" : codeAnchor);
        return sha256(normalized);
    }

    public static String codeAnchor(CodeChunk chunk, int startLine, int endLine) {
        String content = chunk == null ? null : chunk.getContent();
        if (content == null || content.isBlank()) {
            return fallbackAnchor(chunk, startLine, endLine);
        }
        String[] lines = content.split("\\R", -1);
        int first = Math.max(0, startLine - chunk.getStartLine());
        int last = Math.min(lines.length - 1, endLine - chunk.getStartLine());
        if (first > last || first >= lines.length || last < 0) {
            return fallbackAnchor(chunk, startLine, endLine);
        }

        // Include one neighbouring line on each side. This distinguishes repeated
        // identical calls in one method without tying the identity to absolute lines.
        int windowStart = Math.max(0, first - 1);
        int windowEnd = Math.min(lines.length - 1, last + 1);
        String normalizedSource = normalizeLines(lines, windowStart, windowEnd);
        String selectedSource = normalizeLines(lines, first, last);
        return normalizedSource.isEmpty()
                ? fallbackAnchor(chunk, startLine, endLine)
                : sha256(normalizedSource) + ":occurrence:" + occurrence(lines, first, last, selectedSource);
    }

    public static String normalizePath(String value) {
        if (value == null) return "";
        String normalized = value.strip().replace('\\', '/');
        while (normalized.contains("//")) normalized = normalized.replace("//", "/");
        return normalized;
    }

    private static String normalizeSymbol(String value) {
        return value == null ? "" : value.strip().replaceAll("\\s+", "");
    }

    private static String fallbackAnchor(CodeChunk chunk, int startLine, int endLine) {
        int chunkStart = chunk == null ? 0 : chunk.getStartLine();
        int relativeStart = Math.max(0, startLine - chunkStart);
        int relativeEnd = Math.max(relativeStart, endLine - chunkStart);
        return "relative-range:" + relativeStart + "-" + relativeEnd;
    }

    private static String normalizeLines(String[] lines, int start, int end) {
        StringBuilder normalizedSource = new StringBuilder();
        for (int index = start; index <= end; index++) {
            String normalizedLine = normalizeLine(lines[index]);
            if (!normalizedLine.isBlank()) {
                if (!normalizedSource.isEmpty()) normalizedSource.append('\n');
                normalizedSource.append(normalizedLine);
            }
        }
        return normalizedSource.toString();
    }

    private static String normalizeLine(String line) {
        StringBuilder normalized = new StringBuilder();
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaped = false;
        for (int index = 0; index < line.length(); index++) {
            char value = line.charAt(index);
            if (Character.isWhitespace(value) && !inSingleQuote && !inDoubleQuote) continue;
            normalized.append(value);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (value == '\\' && (inSingleQuote || inDoubleQuote)) {
                escaped = true;
            } else if (value == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote;
            } else if (value == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
            }
        }
        return normalized.toString();
    }

    private static int occurrence(String[] lines, int first, int last, String selectedSource) {
        if (selectedSource.isBlank()) return 1;
        int selectedLength = last - first;
        int occurrence = 1;
        for (int candidateStart = 0; candidateStart < first; candidateStart++) {
            int candidateEnd = candidateStart + selectedLength;
            if (candidateEnd >= lines.length) break;
            if (normalizeLines(lines, candidateStart, candidateEnd).equals(selectedSource)) occurrence++;
        }
        return occurrence;
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("无法生成漏洞稳定指纹", exception);
        }
    }
}
