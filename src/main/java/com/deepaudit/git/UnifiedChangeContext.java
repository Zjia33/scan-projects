package com.deepaudit.git;

import org.eclipse.jgit.diff.DiffAlgorithm;
import org.eclipse.jgit.diff.Edit;
import org.eclipse.jgit.diff.EditList;
import org.eclipse.jgit.diff.RawText;
import org.eclipse.jgit.diff.RawTextComparator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 将 Base/Target 差异压缩为以实际变更为中心的统一上下文，不截取方法或文件开头。
 */
public final class UnifiedChangeContext {
    private UnifiedChangeContext() {
    }

    public static String render(String baseContent, String targetContent,
                                Integer baseStartLine, int targetStartLine,
                                int contextLines, int maxChars, boolean includeLineNumbers) {
        RawText base = rawText(baseContent);
        RawText target = rawText(targetContent);
        EditList edits = DiffAlgorithm.getAlgorithm(DiffAlgorithm.SupportedAlgorithm.HISTOGRAM)
                .diff(RawTextComparator.DEFAULT, base, target);
        return render(base, target, edits, baseStartLine, targetStartLine,
                contextLines, maxChars, includeLineNumbers);
    }

    public static String render(String baseContent, String targetContent, List<Edit> edits,
                                Integer baseStartLine, int targetStartLine,
                                int contextLines, int maxChars, boolean includeLineNumbers) {
        return render(rawText(baseContent), rawText(targetContent), edits, baseStartLine,
                targetStartLine, contextLines, maxChars, includeLineNumbers);
    }

    private static String render(RawText base, RawText target, List<Edit> edits,
                                 Integer baseStartLine, int targetStartLine,
                                 int contextLines, int maxChars, boolean includeLineNumbers) {
        if (edits == null || edits.isEmpty()) return "";
        int surroundingLines = Math.max(0, contextLines);
        StringBuilder result = new StringBuilder();
        for (List<Edit> group : groups(edits, base.size(), target.size(), surroundingLines)) {
            appendGroup(result, base, target, group, baseStartLine,
                    Math.max(1, targetStartLine), surroundingLines, includeLineNumbers);
        }
        return limit(result.toString().stripTrailing(), Math.max(500, maxChars));
    }

    private static List<List<Edit>> groups(List<Edit> edits, int baseLines,
                                           int targetLines, int contextLines) {
        List<List<Edit>> result = new ArrayList<>();
        for (Edit edit : edits) {
            if (result.isEmpty()) {
                result.add(new ArrayList<>(List.of(edit)));
                continue;
            }
            List<Edit> current = result.get(result.size() - 1);
            Edit previous = current.get(current.size() - 1);
            boolean overlapsBase = Math.max(0, edit.getBeginA() - contextLines)
                    <= Math.min(baseLines, previous.getEndA() + contextLines);
            boolean overlapsTarget = Math.max(0, edit.getBeginB() - contextLines)
                    <= Math.min(targetLines, previous.getEndB() + contextLines);
            if (overlapsBase && overlapsTarget) {
                current.add(edit);
            } else {
                result.add(new ArrayList<>(List.of(edit)));
            }
        }
        return result;
    }

    private static void appendGroup(StringBuilder result, RawText base, RawText target,
                                    List<Edit> edits, Integer baseStartLine, int targetStartLine,
                                    int contextLines, boolean includeLineNumbers) {
        Edit first = edits.get(0);
        Edit last = edits.get(edits.size() - 1);
        int beginA = Math.max(0, first.getBeginA() - contextLines);
        int endA = Math.min(base.size(), last.getEndA() + contextLines);
        int beginB = Math.max(0, first.getBeginB() - contextLines);
        int endB = Math.min(target.size(), last.getEndB() + contextLines);
        if (!result.isEmpty()) result.append("\n\n");
        result.append("@@ base ").append(range(baseStartLine, beginA, endA))
                .append(" target ").append(range(targetStartLine, beginB, endB)).append(" @@\n");

        int cursorA = beginA;
        int cursorB = beginB;
        for (Edit edit : edits) {
            while (cursorA < edit.getBeginA() && cursorB < edit.getBeginB()) {
                appendLine(result, ' ', target.getString(cursorB), null,
                        targetStartLine + cursorB, includeLineNumbers);
                cursorA++;
                cursorB++;
            }
            for (int index = edit.getBeginA(); index < edit.getEndA(); index++) {
                appendLine(result, '-', base.getString(index), baseStartLine == null
                                ? index + 1 : baseStartLine + index,
                        null, includeLineNumbers);
            }
            for (int index = edit.getBeginB(); index < edit.getEndB(); index++) {
                appendLine(result, '+', target.getString(index), null,
                        targetStartLine + index, includeLineNumbers);
            }
            cursorA = edit.getEndA();
            cursorB = edit.getEndB();
        }
        while (cursorA < endA && cursorB < endB) {
            appendLine(result, ' ', target.getString(cursorB), null,
                    targetStartLine + cursorB, includeLineNumbers);
            cursorA++;
            cursorB++;
        }
    }

    private static void appendLine(StringBuilder result, char marker, String line,
                                   Integer baseLine, Integer targetLine,
                                   boolean includeLineNumbers) {
        result.append(marker).append(' ');
        if (includeLineNumbers) {
            if (baseLine != null) result.append('B').append(baseLine);
            if (targetLine != null) result.append('T').append(targetLine);
            result.append(" | ");
        }
        result.append(line).append('\n');
    }

    private static String range(Integer startLine, int begin, int end) {
        String prefix = startLine == null ? "method+" : "";
        int first = startLine == null ? begin + 1 : startLine + begin;
        if (begin == end) return prefix + first + "-empty";
        int last = startLine == null ? end : startLine + end - 1;
        return prefix + first + "-" + last;
    }

    private static RawText rawText(String value) {
        String safe = value == null ? "" : value;
        return new RawText(safe.getBytes(StandardCharsets.UTF_8));
    }

    private static String limit(String value, int maxChars) {
        if (value.length() <= maxChars) return value;
        String marker = "\n... [CHANGE_CONTEXT_TRUNCATED] ...\n";
        int available = maxChars - marker.length();
        int headTarget = available * 2 / 3;
        int tailTarget = available - headTarget;
        int headEnd = value.lastIndexOf('\n', headTarget);
        if (headEnd < 0) headEnd = headTarget;
        int tailStart = value.indexOf('\n', value.length() - tailTarget);
        if (tailStart < 0) tailStart = value.length() - tailTarget;
        else tailStart++;
        return value.substring(0, headEnd).stripTrailing() + marker
                + value.substring(tailStart).stripLeading();
    }
}
