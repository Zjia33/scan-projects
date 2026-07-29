package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// 封装 AnalyzerSupport 相关的数据与处理逻辑。
final class AnalyzerSupport {

    // 创建 AnalyzerSupport 实例并初始化所需依赖或状态。
    private AnalyzerSupport() {
    }

    // 判断是否满足 containsAny 对应的条件。
    static boolean containsAny(String content, String... tokens) {
        String normalized = content.toLowerCase(Locale.ROOT);
        for (String token : tokens) {
            if (normalized.contains(token.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    // 判断是否满足 matches 对应的条件。
    static boolean matches(String content, String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(content).find();
    }

    // 执行 AnalyzerSupport 中的 matchingLine 处理。
    static int matchingLine(CodeChunk chunk, String regex) {
        Matcher matcher = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(chunk.getContent());
        if (!matcher.find()) {
            return chunk.getStartLine();
        }
        long offset = chunk.getContent().substring(0, matcher.start()).chars().filter(value -> value == '\n').count();
        return chunk.getStartLine() + (int) offset;
    }

    // 执行 AnalyzerSupport 中的 excerpt 处理。
    static String excerpt(CodeChunk chunk, int absoluteLine) {
        String[] lines = chunk.getContent().split("\\R", -1);
        int relative = Math.max(0, absoluteLine - chunk.getStartLine());
        int from = Math.max(0, relative - 2);
        int to = Math.min(lines.length, relative + 3);
        StringBuilder evidence = new StringBuilder();
        for (int index = from; index < to; index++) {
            evidence.append(chunk.getStartLine() + index).append(" | ").append(lines[index]).append('\n');
        }
        return evidence.toString().stripTrailing();
    }

    // 执行 AnalyzerSupport 中的 evidence 处理。
    static String evidence(CodeChunk chunk, int line) {
        return "规则提示（仅作为 Agent 调查起点）：\n" + excerpt(chunk, line);
    }
}
