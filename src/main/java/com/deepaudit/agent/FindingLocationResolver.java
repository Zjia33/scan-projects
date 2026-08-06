package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/** 确定性校验专业 Agent 的源码位置，并生成最终报告所需的紧凑证据窗口。 */
public final class FindingLocationResolver {
    private static final int CONTEXT_LINES = 4;
    private static final int MAX_VULNERABLE_LINES = 5;

    private FindingLocationResolver() {
    }

    public static Location resolve(LlmGateway.FindingProposal proposal, CodeChunk chunk) {
        String description = proposal.title() + " " + proposal.description();
        ScoredLocation inferred = inferLocation(proposal.type(), description, chunk);
        return validateExplicit(proposal.vulnerabilityStartLine(), proposal.vulnerabilityEndLine(), chunk)
                .filter(location -> hasContentInRange(chunk, location))
                .filter(location -> !shouldPreferInferred(proposal.type(), description, chunk, location, inferred))
                .orElse(inferred.location());
    }

    public static Optional<Location> validateExplicit(Integer proposedStart, Integer proposedEnd,
                                                      CodeChunk chunk) {
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = Math.max(chunkStart, chunk.getEndLine());
        if (proposedStart == null || proposedStart < chunkStart || proposedStart > chunkEnd) {
            return Optional.empty();
        }
        int end = proposedEnd == null ? proposedStart : proposedEnd;
        if (end < proposedStart || end > chunkEnd || end - proposedStart + 1 > MAX_VULNERABLE_LINES) {
            return Optional.empty();
        }
        return Optional.of(new Location(proposedStart, end));
    }

    private static Location infer(VulnerabilityType type, String description, CodeChunk chunk) {
        return inferLocation(type, description, chunk).location();
    }

    /**
     * 当一个已确认的直接 caller/callee 关系需要展示时，只接受源码中唯一的调用表达式。
     * 多个同名调用无法可靠区分，宁可不高亮，也不猜测其中某一行。
     */
    public static Optional<Location> uniqueCallSite(CodeChunk caller, CodeChunk callee) {
        if (caller == null || callee == null) return Optional.empty();
        String method = methodName(callee.getSymbolName());
        if (method.isBlank()) return Optional.empty();
        String[] lines = contentLines(caller);
        Pattern qualifiedCall = Pattern.compile("\\.\\s*" + Pattern.quote(method) + "\\s*\\(");
        List<Integer> matches = matchingLines(lines, qualifiedCall, caller.getStartLine());
        if (matches.size() == 1) return Optional.of(new Location(matches.get(0), matches.get(0)));

        String qualifier = lowerCamel(typeName(callee.getSymbolName()));
        if (!qualifier.isBlank()) {
            Pattern qualifiedByType = Pattern.compile("\\b" + Pattern.quote(qualifier)
                    + "\\s*\\.\\s*" + Pattern.quote(method) + "\\s*\\(");
            List<Integer> typedMatches = matchingLines(lines, qualifiedByType, caller.getStartLine());
            if (typedMatches.size() == 1) {
                return Optional.of(new Location(typedMatches.get(0), typedMatches.get(0)));
            }
        }
        return Optional.empty();
    }

    /** 返回缺少校验后真正执行安全敏感操作的位置；普通 return、if 和方法声明不算危险操作。 */
    public static Optional<SinkLocation> concreteSink(LlmGateway.FindingProposal proposal, CodeChunk chunk) {
        if (proposal == null || chunk == null) return Optional.empty();
        List<String> sinks = concretePatterns(proposal.type());
        if (sinks.isEmpty()) return Optional.empty();
        String description = safe(proposal.title()) + " " + safe(proposal.description());
        String[] lines = contentLines(chunk);
        List<SinkLocation> matches = new ArrayList<>();
        int chunkStart = Math.max(1, chunk.getStartLine());
        for (int index = 0; index < lines.length; index++) {
            String source = lines[index].toLowerCase(Locale.ROOT);
            int concreteMatches = 0;
            int priority = 0;
            for (int patternIndex = 0; patternIndex < sinks.size(); patternIndex++) {
                if (!source.contains(sinks.get(patternIndex))) continue;
                concreteMatches++;
                priority = Math.max(priority, sinks.size() - patternIndex);
            }
            if (concreteMatches == 0) continue;
            int score = concreteMatches * 8 + priority * 2 + descriptionTokenScore(description, source);
            int line = chunkStart + index;
            matches.add(new SinkLocation(new Location(line, line), score));
        }
        return matches.stream().max(Comparator.comparingInt(SinkLocation::score));
    }

    private static ScoredLocation inferLocation(VulnerabilityType type, String description, CodeChunk chunk) {
        String[] lines = contentLines(chunk);
        int bestIndex = -1;
        int bestScore = 0;
        for (int index = 0; index < lines.length; index++) {
            int score = scoreLine(type, description, lines[index]);
            if (score > bestScore) {
                bestScore = score;
                bestIndex = index;
            }
        }
        if (bestIndex < 0) bestIndex = firstExecutableLine(lines);
        int line = Math.min(Math.max(1, chunk.getStartLine()) + bestIndex,
                Math.max(Math.max(1, chunk.getStartLine()), chunk.getEndLine()));
        return new ScoredLocation(new Location(line, line), bestScore);
    }

    private static boolean shouldPreferInferred(VulnerabilityType type, String description, CodeChunk chunk,
                                                Location explicit, ScoredLocation inferred) {
        if (inferred.score() < 4 || inferred.location().startLine() >= explicit.startLine()
                && inferred.location().endLine() <= explicit.endLine()) {
            return false;
        }
        int explicitBestScore = 0;
        String[] lines = contentLines(chunk);
        int chunkStart = Math.max(1, chunk.getStartLine());
        for (int line = explicit.startLine(); line <= explicit.endLine(); line++) {
            int index = line - chunkStart;
            if (index >= 0 && index < lines.length) {
                explicitBestScore = Math.max(explicitBestScore, scoreLine(type, description, lines[index]));
            }
        }
        return inferred.score() > explicitBestScore;
    }

    private static int scoreLine(VulnerabilityType type, String description, String sourceLine) {
        String line = sourceLine == null ? "" : sourceLine.toLowerCase(Locale.ROOT);
        int score = 0;
        for (String pattern : patterns(type)) if (line.contains(pattern)) score += 4;
        score += descriptionTokenScore(description, line);
        return score;
    }

    private static int descriptionTokenScore(String description, String sourceLine) {
        String normalizedDescription = description == null ? "" : description.toLowerCase(Locale.ROOT);
        int score = 0;
        for (String token : normalizedDescription.split("[^\\p{L}\\p{N}_$]+")) {
            if (token.length() >= 4 && sourceLine.contains(token)) score++;
        }
        return score;
    }

    public static String formatContext(CodeChunk chunk, Location location, boolean markVulnerability) {
        String[] lines = contentLines(chunk);
        int chunkStart = Math.max(1, chunk.getStartLine());
        int contentEnd = Math.min(Math.max(chunkStart, chunk.getEndLine()),
                chunkStart + lines.length - 1);
        int first = Math.max(chunkStart, location.startLine() - CONTEXT_LINES);
        int last = Math.min(contentEnd, location.endLine() + CONTEXT_LINES);
        StringBuilder result = new StringBuilder();
        if (first > chunkStart) result.append("      …\n");
        for (int lineNumber = first; lineNumber <= last; lineNumber++) {
            int index = lineNumber - chunkStart;
            if (index < 0 || index >= lines.length) continue;
            boolean vulnerable = markVulnerability
                    && lineNumber >= location.startLine() && lineNumber <= location.endLine();
            result.append(vulnerable ? ">>> " : "    ")
                    .append(String.format(Locale.ROOT, "%5d | ", lineNumber))
                    .append(lines[index]).append('\n');
        }
        if (last < contentEnd) result.append("      …\n");
        return result.toString().stripTrailing();
    }

    public static String formatEvidence(LlmGateway.FindingProposal proposal,
                                        Map<Long, CodeChunk> chunks,
                                        Map<Long, Integer> callSiteLines) {
        List<Long> orderedIds = new ArrayList<>();
        orderedIds.add(proposal.primaryChunkId());
        proposal.evidenceChunkIds().stream().filter(id -> !orderedIds.contains(id)).forEach(orderedIds::add);
        return orderedIds.stream().distinct().map(chunks::get)
                .filter(java.util.Objects::nonNull)
                // 证据块可能来自删除方法、缺失源码或数据库中的历史记录。没有可渲染源码时，
                // 不能仅凭块的文件名和行号生成看似可信的证据卡片。
                .filter(FindingLocationResolver::hasRenderableContent)
                .map(chunk -> {
                    boolean primary = chunk.getId().equals(proposal.primaryChunkId());
                    Integer callSiteLine = callSiteLines.get(chunk.getId());
                    Optional<Location> relatedLocation = primary
                            ? Optional.empty() : validCallSite(callSiteLine, chunk);
                    Location location = primary ? resolve(proposal, chunk)
                            : relatedLocation.orElseGet(() -> infer(proposal.type(),
                            safe(proposal.title()) + " " + safe(proposal.description()), chunk));
                    String label = primary ? "[漏洞位置]" : relatedLocation.isPresent()
                            ? chunk.getEndpoint() == null || chunk.getEndpoint().isBlank()
                            ? "[调用链]" : "[调用入口]" : "[关联证据]";
                    String displayedRange = primary || relatedLocation.isPresent()
                            ? location.startLine()
                            + (location.endLine() == location.startLine() ? "" : "-" + location.endLine())
                            : chunk.getStartLine() + (chunk.getEndLine() == chunk.getStartLine()
                            ? "" : "-" + chunk.getEndLine());
                    return "[CHUNK " + chunk.getId() + "] " + label + " " + chunk.getFilePath() + ":"
                            + displayedRange + " " + chunk.getSymbolName() + "\n"
                            + formatContext(chunk, location, primary);
                }).filter(java.util.Objects::nonNull).collect(Collectors.joining("\n\n"));
    }

    private static List<Integer> matchingLines(String[] lines, Pattern pattern, int startLine) {
        List<Integer> result = new ArrayList<>();
        int normalizedStart = Math.max(1, startLine);
        for (int index = 0; index < lines.length; index++) {
            if (pattern.matcher(lines[index]).find()) result.add(normalizedStart + index);
        }
        return result;
    }

    private static String methodName(String symbol) {
        if (symbol == null) return "";
        String value = symbol.strip();
        int parameters = value.indexOf('(');
        if (parameters >= 0) value = value.substring(0, parameters);
        int separator = Math.max(value.lastIndexOf('#'), value.lastIndexOf('.'));
        return separator < 0 ? value : value.substring(separator + 1);
    }

    private static String typeName(String symbol) {
        if (symbol == null) return "";
        String value = symbol.strip();
        int separator = value.lastIndexOf('#');
        if (separator >= 0) value = value.substring(0, separator);
        int packageSeparator = value.lastIndexOf('.');
        return packageSeparator < 0 ? value : value.substring(packageSeparator + 1);
    }

    private static String lowerCamel(String value) {
        if (value == null || value.isBlank()) return "";
        return Character.toLowerCase(value.charAt(0)) + value.substring(1);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static Optional<Location> validCallSite(Integer line, CodeChunk chunk) {
        return validateExplicit(line, line, chunk)
                .filter(location -> hasContentAtLine(chunk, location.startLine()));
    }

    private static boolean hasRenderableContent(CodeChunk chunk) {
        for (String line : contentLines(chunk)) {
            if (!line.isBlank()) return true;
        }
        return false;
    }

    private static boolean hasContentAtLine(CodeChunk chunk, int lineNumber) {
        int start = Math.max(1, chunk.getStartLine());
        int index = lineNumber - start;
        String[] lines = contentLines(chunk);
        return index >= 0 && index < lines.length && !lines[index].isBlank();
    }

    private static boolean hasContentInRange(CodeChunk chunk, Location location) {
        for (int line = location.startLine(); line <= location.endLine(); line++) {
            if (hasContentAtLine(chunk, line)) return true;
        }
        return false;
    }

    private static String[] contentLines(CodeChunk chunk) {
        String content = chunk.getContent() == null ? "" : chunk.getContent();
        return content.split("\\R", -1);
    }

    private static int firstExecutableLine(String[] lines) {
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index].strip();
            if (!line.isEmpty() && !line.startsWith("@") && !line.endsWith("{")
                    && !line.equals("}")) return index;
        }
        return 0;
    }

    private static List<String> patterns(VulnerabilityType type) {
        return switch (type) {
            case SQL_INJECTION -> List.of("execute(", "executequery", "executeupdate", "statement.",
                    "queryfor", "createnativequery", "${", "select ", "insert ", "update ", "delete ");
            case AUTHORIZATION -> List.of("findbyid", "delete", "update", "save(", "owner", "userid",
                    "accountid", "tenant", "transfer", "withdraw", "purchase");
            case SENSITIVE_INFORMATION_DISCLOSURE -> List.of("password", "secret", "api-key", "apikey",
                    "access-key", "private-key", "client-secret", "token", "return ", "response", "body(");
            case STORED_XSS -> List.of("v-html", "innerhtml", "outerhtml", "document.write", "th:utext",
                    "<%=", "append(", "html(");
            case VALIDATION_BYPASS -> List.of("validate", "isvalid", "if (", "if(", "return ", "save(",
                    "execute(", "multiply(", "debit(", "credit(", "transfer(", "charge(");
        };
    }

    private static List<String> concretePatterns(VulnerabilityType type) {
        return switch (type) {
            case SQL_INJECTION -> List.of("execute(", "executequery", "executeupdate", "statement.",
                    "queryfor", "createnativequery", "${");
            case VALIDATION_BYPASS -> List.of("multiply(", "debit(", "credit(", "transfer(",
                    "withdraw(", "charge(", "save(", "execute(", "update(", "delete(");
            case STORED_XSS -> List.of("innerhtml", "outerhtml", "document.write", "th:utext",
                    "<%=", "append(", "html(");
            case AUTHORIZATION, SENSITIVE_INFORMATION_DISCLOSURE -> List.of();
        };
    }

    private record ScoredLocation(Location location, int score) {
    }

    public record SinkLocation(Location location, int score) {
    }

    public record Location(int startLine, int endLine) {
    }
}
