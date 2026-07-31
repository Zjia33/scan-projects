package com.deepaudit.analysis;

import com.deepaudit.agent.FindingFingerprint;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Finding;
import com.deepaudit.domain.FindingDeltaStatus;
import com.deepaudit.domain.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Performs authoritative task-local deduplication after Critic relocation.
 */
public final class FindingConsolidator {
    private static final Pattern EVIDENCE_CHUNK_HEADER =
            Pattern.compile("(?m)^\\[CHUNK\\s+(\\d+)]");

    private FindingConsolidator() {
    }

    public static List<Finding> consolidate(List<Finding> findings, List<CodeChunk> chunks) {
        List<Finding> consolidated = new ArrayList<>();
        if (findings == null) return consolidated;
        List<CodeChunk> safeChunks = chunks == null ? List.of() : chunks;
        for (Finding finding : findings) {
            if (finding == null) continue;
            consolidated.add(finding);
        }
        collapseOverlaps(consolidated, safeChunks);
        consolidated.forEach(finding -> refreshFingerprint(finding, safeChunks));
        return consolidated;
    }

    private static void collapseOverlaps(List<Finding> consolidated, List<CodeChunk> chunks) {
        boolean merged;
        do {
            merged = false;
            outer:
            for (int left = 0; left < consolidated.size(); left++) {
                for (int right = left + 1; right < consolidated.size(); right++) {
                    if (!sameVulnerabilityLocation(
                            consolidated.get(left), consolidated.get(right), chunks)) {
                        continue;
                    }
                    mergeInto(consolidated.get(left), consolidated.remove(right));
                    merged = true;
                    break outer;
                }
            }
        } while (merged);
    }

    private static boolean sameVulnerabilityLocation(Finding left, Finding right,
                                                     List<CodeChunk> chunks) {
        if (!Objects.equals(left.getTaskId(), right.getTaskId()) || left.getType() != right.getType()) {
            return false;
        }
        if (!FindingFingerprint.normalizePath(left.getFilePath())
                .equals(FindingFingerprint.normalizePath(right.getFilePath()))) {
            return false;
        }
        if (!rangesOverlap(left, right)) return false;
        String leftSymbol = symbolAt(left, chunks);
        String rightSymbol = symbolAt(right, chunks);
        return leftSymbol.isBlank() || rightSymbol.isBlank() || leftSymbol.equals(rightSymbol);
    }

    private static boolean rangesOverlap(Finding left, Finding right) {
        return left.getStartLine() > 0 && right.getStartLine() > 0
                && left.getStartLine() <= right.getEndLine()
                && right.getStartLine() <= left.getEndLine();
    }

    private static void mergeInto(Finding target, Finding duplicate) {
        target.setSeverity(stronger(target.getSeverity(), duplicate.getSeverity()));
        target.setConfidence(stronger(target.getConfidence(), duplicate.getConfidence()));
        target.setTitle(specific(target.getTitle(), duplicate.getTitle()));
        target.setStartLine(Math.min(target.getStartLine(), duplicate.getStartLine()));
        target.setEndLine(Math.max(target.getEndLine(), duplicate.getEndLine()));
        target.setEndpoint(mergeEndpoints(target.getEndpoint(), duplicate.getEndpoint()));
        target.setDescription(specific(target.getDescription(), duplicate.getDescription()));
        target.setEvidence(mergeEvidence(target.getEvidence(), duplicate.getEvidence()));
        target.setRemediation(specific(target.getRemediation(), duplicate.getRemediation()));
        target.setDeltaStatus(stronger(target.getDeltaStatus(), duplicate.getDeltaStatus()));
        target.setCreatedAt(earlier(target.getCreatedAt(), duplicate.getCreatedAt()));
    }

    private static void refreshFingerprint(Finding finding, List<CodeChunk> chunks) {
        CodeChunk chunk = chunkAt(finding, chunks);
        String symbol = chunk == null ? "" : chunk.getSymbolName();
        String anchor = chunk == null
                ? "line-range:" + finding.getStartLine() + "-" + finding.getEndLine()
                : FindingFingerprint.codeAnchor(chunk, finding.getStartLine(), finding.getEndLine());
        finding.setFingerprint(FindingFingerprint.create(
                finding.getType(), finding.getFilePath(), symbol, anchor));
    }

    private static String symbolAt(Finding finding, List<CodeChunk> chunks) {
        CodeChunk chunk = chunkAt(finding, chunks);
        return chunk == null || chunk.getSymbolName() == null
                ? "" : chunk.getSymbolName().strip().replaceAll("\\s+", "");
    }

    private static CodeChunk chunkAt(Finding finding, List<CodeChunk> chunks) {
        String path = FindingFingerprint.normalizePath(finding.getFilePath());
        return chunks.stream()
                .filter(Objects::nonNull)
                .filter(chunk -> FindingFingerprint.normalizePath(chunk.getFilePath()).equals(path))
                .filter(chunk -> chunk.getStartLine() <= finding.getStartLine()
                        && chunk.getEndLine() >= finding.getEndLine())
                .min(Comparator.comparingInt(chunk -> chunk.getEndLine() - chunk.getStartLine()))
                .orElseGet(() -> chunks.stream()
                        .filter(Objects::nonNull)
                        .filter(chunk -> FindingFingerprint.normalizePath(chunk.getFilePath()).equals(path))
                        .filter(chunk -> chunk.getStartLine() <= finding.getEndLine()
                                && finding.getStartLine() <= chunk.getEndLine())
                        .min(Comparator.comparingInt(chunk -> chunk.getEndLine() - chunk.getStartLine()))
                        .orElse(null));
    }

    private static Severity stronger(Severity left, Severity right) {
        if (left == null) return right;
        if (right == null) return left;
        return left.ordinal() <= right.ordinal() ? left : right;
    }

    private static Confidence stronger(Confidence left, Confidence right) {
        if (left == null) return right;
        if (right == null) return left;
        return left.ordinal() <= right.ordinal() ? left : right;
    }

    private static FindingDeltaStatus stronger(FindingDeltaStatus left, FindingDeltaStatus right) {
        if (left == null) return right;
        if (right == null) return left;
        return deltaRank(left) >= deltaRank(right) ? left : right;
    }

    private static int deltaRank(FindingDeltaStatus value) {
        return switch (value) {
            case NEW, REGRESSED, AFFECTED -> 3;
            case PERSISTING -> 2;
            case BASELINE -> 1;
        };
    }

    private static String specific(String left, String right) {
        String first = left == null ? "" : left.strip();
        String second = right == null ? "" : right.strip();
        if (first.length() != second.length()) return first.length() > second.length() ? first : second;
        return first.compareTo(second) <= 0 ? first : second;
    }

    private static String mergeEndpoints(String left, String right) {
        Set<String> values = new LinkedHashSet<>();
        addEndpoints(values, left);
        addEndpoints(values, right);
        if (values.isEmpty()) return null;
        StringBuilder result = new StringBuilder();
        for (String value : values) {
            String separator = result.isEmpty() ? "" : ", ";
            if (result.length() + separator.length() + value.length() > 500) break;
            result.append(separator).append(value);
        }
        return result.isEmpty() ? values.iterator().next().substring(
                0, Math.min(500, values.iterator().next().length())) : result.toString();
    }

    private static void addEndpoints(Set<String> endpoints, String value) {
        if (value == null || value.isBlank()) return;
        Arrays.stream(value.split("\\s*,\\s*"))
                .map(String::strip)
                .filter(endpoint -> !endpoint.isBlank())
                .forEach(endpoints::add);
    }

    private static String mergeText(String left, String right) {
        String first = left == null ? "" : left.strip();
        String second = right == null ? "" : right.strip();
        if (first.isBlank()) return second;
        if (second.isBlank() || first.equals(second)) return first;
        return first + "\n\n---\n\n" + second;
    }

    private static String mergeEvidence(String left, String right) {
        String first = left == null ? "" : left.strip();
        String second = right == null ? "" : right.strip();
        if (first.isBlank()) return second;
        if (second.isBlank() || first.equals(second)) return first;

        Map<Long, String> firstBlocks = evidenceBlocks(first);
        Map<Long, String> secondBlocks = evidenceBlocks(second);
        if (firstBlocks.isEmpty() || secondBlocks.isEmpty()) {
            return mergeText(first, second);
        }

        LinkedHashMap<Long, String> merged = new LinkedHashMap<>(firstBlocks);
        secondBlocks.forEach((chunkId, block) ->
                merged.merge(chunkId, block, FindingConsolidator::preferredEvidenceBlock));
        return String.join("\n\n", merged.values());
    }

    private static Map<Long, String> evidenceBlocks(String evidence) {
        LinkedHashMap<Long, String> blocks = new LinkedHashMap<>();
        Matcher matcher = EVIDENCE_CHUNK_HEADER.matcher(evidence);
        List<EvidenceHeader> headers = new ArrayList<>();
        while (matcher.find()) {
            try {
                headers.add(new EvidenceHeader(Long.parseLong(matcher.group(1)), matcher.start()));
            } catch (NumberFormatException ignored) {
                // A malformed model-generated header is kept by the unstructured fallback.
                return Map.of();
            }
        }
        for (int index = 0; index < headers.size(); index++) {
            EvidenceHeader header = headers.get(index);
            int end = index + 1 < headers.size() ? headers.get(index + 1).offset() : evidence.length();
            String block = evidence.substring(header.offset(), end).strip();
            blocks.merge(header.chunkId(), block, FindingConsolidator::preferredEvidenceBlock);
        }
        return blocks;
    }

    private static String preferredEvidenceBlock(String left, String right) {
        int leftRank = evidenceRoleRank(left);
        int rightRank = evidenceRoleRank(right);
        if (leftRank != rightRank) return leftRank > rightRank ? left : right;
        return left.length() >= right.length() ? left : right;
    }

    private static int evidenceRoleRank(String block) {
        if (block.contains("[漏洞位置]")) return 4;
        if (block.contains("[调用入口]")) return 3;
        if (block.contains("[调用链]")) return 2;
        if (block.contains("[关联证据]")) return 1;
        return 0;
    }

    private record EvidenceHeader(long chunkId, int offset) {
    }

    private static Instant earlier(Instant left, Instant right) {
        if (left == null) return right;
        if (right == null) return left;
        return left.isBefore(right) ? left : right;
    }
}
