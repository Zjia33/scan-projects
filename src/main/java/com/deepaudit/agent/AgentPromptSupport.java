package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class AgentPromptSupport {
    private static final int TARGET_HEAD_CHARS = 4_000;
    private static final int BASE_HEAD_CHARS = 2_000;
    private static final Pattern NUMBERED_SOURCE_LINE = Pattern.compile("^\\s*(\\d+)\\s+\\| ?(.*)$");

    private AgentPromptSupport() {
    }

    static LlmGateway.Target target(CodeChunk chunk, Set<VulnerabilityType> hints) {
        return target(chunk, hints, "", "");
    }

    static LlmGateway.Target target(CodeChunk chunk, Set<VulnerabilityType> hints,
                                    String baseChangeExcerpt, String targetChangeExcerpt) {
        String content = chunk.getContent() == null ? "" : chunk.getContent();
        String baseContent = chunk.getBaseContent() == null ? "" : chunk.getBaseContent();
        return new LlmGateway.Target(chunk.getId(), chunk.getFilePath(), chunk.getSymbolName(),
                chunk.getEndpoint(), chunk.getChunkType(), chunk.getParameters(), chunk.getAnnotations(),
                chunk.getCalledSymbols(), numberedExcerpt(content, chunk.getStartLine(),
                TARGET_HEAD_CHARS, coveredLineNumbers(targetChangeExcerpt, content, chunk.getStartLine())),
                chunk.getChangeType().name(), chunk.getAnalysisScope().name(),
                baseExcerpt(baseContent, baseChangeExcerpt, BASE_HEAD_CHARS),
                hints == null ? List.of() : List.copyOf(hints), chunk.getStartLine(), chunk.getEndLine());
    }

    private static String numberedExcerpt(String content, int startLine, int maxChars,
                                          Set<Integer> coveredLines) {
        String[] lines = content.split("\\R", -1);
        StringBuilder excerpt = new StringBuilder();
        boolean hasOverlap = coveredLines.stream()
                .anyMatch(line -> line >= startLine && line < startLine + lines.length);
        if (hasOverlap) excerpt.append("[与 Triage Target 变更窗口重复的行已省略]\n");
        for (int index = 0; index < lines.length; index++) {
            int lineNumber = startLine + index;
            if (coveredLines.contains(lineNumber)) continue;
            String numbered = lineNumber + " | " + lines[index] + "\n";
            if (excerpt.length() + numbered.length() > maxChars) {
                int remaining = maxChars - excerpt.length();
                if (remaining > 0) excerpt.append(numbered, 0, Math.min(remaining, numbered.length()));
                break;
            }
            excerpt.append(numbered);
        }
        return excerpt.toString().stripTrailing();
    }

    private static String baseExcerpt(String content, String changeExcerpt, int maxChars) {
        if (content.isBlank()) return "";
        Set<String> coveredLines = coveredSourceLines(changeExcerpt);
        boolean hasOverlap = java.util.Arrays.stream(content.split("\\R", -1))
                .map(String::strip).anyMatch(line -> substantive(line) && coveredLines.contains(line));
        if (!hasOverlap) return content.substring(0, Math.min(maxChars, content.length()));

        StringBuilder excerpt = new StringBuilder("[与 Triage Base 变更窗口重复的行已省略]\n");
        for (String line : content.split("\\R", -1)) {
            String normalized = line.strip();
            if (substantive(normalized) && coveredLines.contains(normalized)) continue;
            String candidate = line + "\n";
            if (excerpt.length() + candidate.length() > maxChars) break;
            excerpt.append(candidate);
        }
        return excerpt.toString().stripTrailing();
    }

    private static Set<Integer> coveredLineNumbers(String excerpt, String content, int contentStartLine) {
        Set<Integer> result = new LinkedHashSet<>();
        if (excerpt == null || excerpt.isBlank()) return result;
        String[] sourceLines = content.split("\\R", -1);
        excerpt.lines().forEach(line -> {
            Matcher matcher = NUMBERED_SOURCE_LINE.matcher(line);
            if (!matcher.matches()) return;
            try {
                int lineNumber = Integer.parseInt(matcher.group(1));
                int sourceIndex = lineNumber - contentStartLine;
                if (sourceIndex >= 0 && sourceIndex < sourceLines.length
                        && sourceLines[sourceIndex].equals(matcher.group(2))) {
                    result.add(lineNumber);
                }
            } catch (NumberFormatException ignored) {
            }
        });
        return Set.copyOf(result);
    }

    private static Set<String> coveredSourceLines(String excerpt) {
        Set<String> result = new LinkedHashSet<>();
        if (excerpt == null || excerpt.isBlank()) return result;
        excerpt.lines().forEach(line -> {
            Matcher matcher = NUMBERED_SOURCE_LINE.matcher(line);
            if (!matcher.matches()) return;
            String source = matcher.group(2).strip();
            if (substantive(source)) result.add(source);
        });
        return Set.copyOf(result);
    }

    private static boolean substantive(String line) {
        return line != null && line.length() >= 6
                && line.chars().anyMatch(character -> Character.isLetterOrDigit(character)
                || character == '@' || character == '_' || character == '"' || character == '\'');
    }
}
