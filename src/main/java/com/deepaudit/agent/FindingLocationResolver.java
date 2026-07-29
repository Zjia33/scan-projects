package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;

import java.util.List;
import java.util.Locale;

public final class FindingLocationResolver {
    private static final int CONTEXT_LINES = 4;
    private static final int MAX_VULNERABLE_LINES = 5;

    private FindingLocationResolver() {
    }

    public static Location resolve(LlmGateway.FindingProposal proposal, CodeChunk chunk) {
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = Math.max(chunkStart, chunk.getEndLine());
        Integer proposedStart = proposal.vulnerabilityStartLine();
        if (proposedStart != null && proposedStart >= chunkStart && proposedStart <= chunkEnd) {
            int proposedEnd = proposal.vulnerabilityEndLine() == null ? proposedStart
                    : proposal.vulnerabilityEndLine();
            int end = Math.max(proposedStart, Math.min(chunkEnd,
                    Math.min(proposedEnd, proposedStart + MAX_VULNERABLE_LINES - 1)));
            return new Location(proposedStart, end);
        }
        return infer(proposal.type(), proposal.title() + " " + proposal.description(), chunk);
    }

    public static Location infer(VulnerabilityType type, String description, CodeChunk chunk) {
        String[] lines = contentLines(chunk);
        List<String> patterns = patterns(type);
        int bestIndex = -1;
        int bestScore = 0;
        String normalizedDescription = description == null ? "" : description.toLowerCase(Locale.ROOT);
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index].toLowerCase(Locale.ROOT);
            int score = 0;
            for (String pattern : patterns) {
                if (line.contains(pattern)) score += 4;
            }
            for (String token : normalizedDescription.split("[^\\p{L}\\p{N}_$]+")) {
                if (token.length() >= 4 && line.contains(token)) score++;
            }
            if (score > bestScore) {
                bestScore = score;
                bestIndex = index;
            }
        }
        if (bestIndex < 0) bestIndex = firstExecutableLine(lines);
        int line = Math.min(Math.max(1, chunk.getStartLine()) + bestIndex,
                Math.max(Math.max(1, chunk.getStartLine()), chunk.getEndLine()));
        return new Location(line, line);
    }

    public static String formatContext(CodeChunk chunk, Location location, boolean markVulnerability) {
        String[] lines = contentLines(chunk);
        int chunkStart = Math.max(1, chunk.getStartLine());
        int first = Math.max(chunkStart, location.startLine() - CONTEXT_LINES);
        int last = Math.min(chunkStart + lines.length - 1, location.endLine() + CONTEXT_LINES);
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
        if (last < chunkStart + lines.length - 1) result.append("      …\n");
        return result.toString().stripTrailing();
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
            case UNAUTHORIZED_DISCLOSURE -> List.of("return ", "find", "load", "get", "response", "body(");
            case STORED_XSS -> List.of("v-html", "innerhtml", "outerhtml", "document.write", "th:utext",
                    "<%=", "append(", "html(");
            case VALIDATION_BYPASS -> List.of("validate", "isvalid", "if (", "if(", "return ", "save(",
                    "execute(");
            case FINANCIAL_RISK -> List.of("price", "amount", "balance", "total", "transfer", "withdraw",
                    "deposit", "purchase", "debit", "credit");
        };
    }

    public static String formatEvidence(LlmGateway.FindingProposal proposal,
                                        java.util.Map<Long, CodeChunk> chunks) {
        return proposal.evidenceChunkIds().stream().distinct().map(chunks::get)
                .filter(java.util.Objects::nonNull)
                .map(chunk -> {
                    boolean primary = chunk.getId().equals(proposal.primaryChunkId());
                    Location location = primary ? resolve(proposal, chunk)
                            : infer(proposal.type(), proposal.description(), chunk);
                    String label = primary ? "[漏洞位置]" : "[关联证据]";
                    return "[CHUNK " + chunk.getId() + "] " + label + " " + chunk.getFilePath() + ":"
                            + location.startLine()
                            + (location.endLine() == location.startLine() ? "" : "-" + location.endLine())
                            + " " + chunk.getSymbolName() + "\n" + formatContext(chunk, location, primary);
                })
                .collect(java.util.stream.Collectors.joining("\n\n"));
    }

    public record Location(int startLine, int endLine) {
    }
}
