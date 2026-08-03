package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

// 封装 FindingLocationResolver 相关的数据与处理逻辑。
public final class FindingLocationResolver {
    private static final int CONTEXT_LINES = 4;
    private static final int CRITIC_PRIMARY_CONTEXT_LINES = 20;
    private static final int CRITIC_RELATED_CONTEXT_LINES = 12;
    private static final int CRITIC_PRIMARY_MAX_CHARS = 6_000;
    private static final int CRITIC_RELATED_MAX_CHARS = 4_000;
    private static final int CRITIC_TOTAL_MAX_CHARS = 20_000;
    private static final int MAX_VULNERABLE_LINES = 5;

    // 创建 FindingLocationResolver 实例并初始化所需依赖或状态。
    private FindingLocationResolver() {
    }

    // 解析并确定 resolve 对应的目标。
    public static Location resolve(LlmGateway.FindingProposal proposal, CodeChunk chunk) {
        return validateExplicit(proposal.vulnerabilityStartLine(), proposal.vulnerabilityEndLine(), chunk)
                .orElseGet(() -> infer(proposal.type(), proposal.title() + " " + proposal.description(), chunk));
    }

    // 严格校验模型或 Critic 返回的位置；无效范围不能被静默裁剪后写入最终报告。
    public static Optional<Location> validateExplicit(Integer proposedStart, Integer proposedEnd, CodeChunk chunk) {
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = Math.max(chunkStart, chunk.getEndLine());
        if (proposedStart == null || proposedStart < chunkStart || proposedStart > chunkEnd) return Optional.empty();
        int end = proposedEnd == null ? proposedStart : proposedEnd;
        if (end < proposedStart || end > chunkEnd || end - proposedStart + 1 > MAX_VULNERABLE_LINES) {
            return Optional.empty();
        }
        return Optional.of(new Location(proposedStart, end));
    }

    /**
     * 对 Critic 的最终定位执行根因感知校验。最终位置不仅要落在真实代码块内，还必须具有与漏洞根因
     * 相符的代码角色；方法安全未启用等控制失效场景会确定性地重定位到失效的安全边界。
     */
    public static Optional<ResolvedPrimary> resolveCriticPrimary(
            LlmGateway.FindingProposal proposal, LlmGateway.CriticDecision decision,
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        return resolveCriticLocation(proposal, decision, chunks, allowedChunkIds,
                locationCandidates(chunks, allowedChunkIds)).resolved();
    }

    /**
     * 分级解析 Critic 位置。模型声明的根因、角色和行号是定位提示；只有服务器生成的候选 ID、
     * 真实代码块边界以及验证过的证据范围属于硬约束。
     */
    public static LocationResolution resolveCriticLocation(
            LlmGateway.FindingProposal proposal, LlmGateway.CriticDecision decision,
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds,
            List<LlmGateway.LocationCandidate> candidates) {
        if (hasText(decision.locationCandidateId())) {
            Optional<ResolvedPrimary> selected = resolveCandidate(
                    decision.locationCandidateId(), candidates);
            if (selected.isPresent()) {
                return new LocationResolution(LocationStatus.EXACT, selected,
                        "Critic 选择了服务器生成的真实源码位置候选");
            }
        }

        RootCause rootCause = rootCause(proposal, decision);
        if (rootCause == RootCause.INEFFECTIVE_SECURITY_CONTROL) {
            Optional<ResolvedPrimary> boundary = ineffectiveSecurityBoundary(chunks, allowedChunkIds);
            return boundary.isPresent()
                    ? new LocationResolution(LocationStatus.NORMALIZED, boundary,
                    "已按失效安全控制根因重定位到真实安全边界")
                    : LocationResolution.unresolved("证据范围内没有可定位的安全边界或安全配置");
        }

        CodeChunk selected = chunks.get(decision.primaryChunkId());
        if (selected != null && allowedChunkIds.contains(selected.getId())) {
            Optional<Location> explicit = validateExplicit(
                    decision.vulnerabilityStartLine(), decision.vulnerabilityEndLine(), selected);
            if (explicit.isPresent()) {
                Set<LocationRole> actualRoles = roles(selected, explicit.get());
                LocationRole acceptedRole = actualRoles.stream()
                        .filter(allowedRoles(rootCause)::contains).findFirst().orElse(null);
                if (acceptedRole != null) {
                    return new LocationResolution(LocationStatus.EXACT,
                            Optional.of(new ResolvedPrimary(selected.getId(), explicit.get(), acceptedRole.name())),
                            "Critic 行号位于真实证据块内并符合根因代码角色");
                }
            }
        }

        Optional<ResolvedPrimary> normalized = bestDeterministicCandidate(
                proposal, decision, rootCause, candidates);
        if (normalized.isPresent()) {
            return new LocationResolution(LocationStatus.NORMALIZED, normalized,
                    "Critic 原始位置不精确，已根据根因和真实源码候选确定性重定位");
        }
        return LocationResolution.unresolved(locationFailureReason(decision, selected, allowedChunkIds));
    }

    // 从验证过的证据代码块生成稳定候选 ID；Java 优先使用 AST 表达式，其他文本使用真实源码行。
    public static List<LlmGateway.LocationCandidate> locationCandidates(
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        List<LlmGateway.LocationCandidate> result = new ArrayList<>();
        for (Long chunkId : allowedChunkIds) {
            CodeChunk chunk = chunks.get(chunkId);
            if (chunk == null) continue;
            String[] lines = contentLines(chunk);
            Map<String, SourceRange> ranges = new LinkedHashMap<>();
            if (isJavaChunk(chunk)) {
                for (SourceRange range : javaSourceRanges(chunk.getContent(), lines.length)) {
                    ranges.putIfAbsent(range.start() + ":" + range.end(), range);
                }
            }
            for (int index = 0; index < lines.length; index++) {
                if (!roles(lines[index]).isEmpty()) {
                    int relative = index + 1;
                    ranges.putIfAbsent(relative + ":" + relative, new SourceRange(relative, relative));
                }
            }
            if (ranges.isEmpty()) {
                for (int index = 0; index < lines.length; index++) {
                    if (isExecutableCandidate(lines[index])) {
                        int relative = index + 1;
                        ranges.put(relative + ":" + relative, new SourceRange(relative, relative));
                    }
                }
            }
            int chunkStart = Math.max(1, chunk.getStartLine());
            for (SourceRange relative : ranges.values().stream()
                    .sorted(Comparator.comparingInt(SourceRange::start).thenComparingInt(SourceRange::end)).toList()) {
                int start = chunkStart + relative.start() - 1;
                int end = chunkStart + relative.end() - 1;
                String source = source(lines, relative.start(), relative.end());
                List<String> detectedRoles = roles(source).stream().map(Enum::name).sorted().toList();
                String candidateId = chunk.getId() + ":" + start + "-" + end;
                result.add(new LlmGateway.LocationCandidate(candidateId, chunk.getId(), chunk.getFilePath(),
                        chunk.getSymbolName(), start, end, source, detectedRoles,
                        chunk.getAnalysisScope() == null ? "" : chunk.getAnalysisScope().name()));
            }
        }
        return List.copyOf(result);
    }

    // 将位置修复模型返回的候选 ID 映射回服务器掌握的真实文件和行号。
    public static Optional<ResolvedPrimary> resolveCandidate(
            String candidateId, List<LlmGateway.LocationCandidate> candidates) {
        if (!hasText(candidateId)) return Optional.empty();
        return candidates.stream().filter(candidate -> candidate.candidateId().equals(candidateId))
                .findFirst().map(candidate -> new ResolvedPrimary(candidate.chunkId(),
                        new Location(candidate.startLine(), candidate.endLine()),
                        candidate.roles().isEmpty() ? "UNCLASSIFIED" : candidate.roles().get(0)));
    }

    // 对“安全控制未启用/不生效”选择真正失效的注解或安全配置行，拒绝把下游数据读取当作根因。
    private static Optional<ResolvedPrimary> ineffectiveSecurityBoundary(
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        ResolvedCandidate best = null;
        for (Long chunkId : allowedChunkIds) {
            CodeChunk chunk = chunks.get(chunkId);
            if (chunk == null) continue;
            String[] lines = contentLines(chunk);
            int chunkStart = Math.max(1, chunk.getStartLine());
            for (int index = 0; index < lines.length; index++) {
                Set<LocationRole> lineRoles = roles(lines[index]);
                LocationRole role = lineRoles.contains(LocationRole.SECURITY_BOUNDARY)
                        ? LocationRole.SECURITY_BOUNDARY
                        : lineRoles.contains(LocationRole.SECURITY_CONFIGURATION)
                        ? LocationRole.SECURITY_CONFIGURATION : null;
                if (role == null) continue;
                int score = boundaryScore(chunk, lines[index], role);
                ResolvedCandidate candidate = new ResolvedCandidate(chunk.getId(),
                        new Location(chunkStart + index, chunkStart + index), role, score);
                if (best == null || candidate.score() > best.score()) best = candidate;
            }
        }
        if (best == null) return Optional.empty();
        return Optional.of(new ResolvedPrimary(best.chunkId(), best.location(), best.role().name()));
    }

    // 安全注解比普通安全配置更接近“失效控制”的使用位置，端点上的注解优先级最高。
    private static int boundaryScore(CodeChunk chunk, String line, LocationRole role) {
        String normalized = line.toLowerCase(Locale.ROOT);
        int score = role == LocationRole.SECURITY_BOUNDARY ? 100 : 50;
        if (containsAny(normalized, "@preauthorize", "@postauthorize", "@secured", "@rolesallowed")) {
            score += 100;
        }
        if (chunk.getEndpoint() != null && !chunk.getEndpoint().isBlank()) score += 25;
        return score;
    }

    private static Optional<ResolvedPrimary> bestDeterministicCandidate(
            LlmGateway.FindingProposal proposal, LlmGateway.CriticDecision decision,
            RootCause rootCause, List<LlmGateway.LocationCandidate> candidates) {
        LocationRole declared = parseRole(decision.locationRole()).orElse(null);
        String claim = String.join(" ", safe(proposal.title()), safe(proposal.description()),
                safe(decision.reason())).toLowerCase(Locale.ROOT);
        List<RankedLocation> ranked = candidates.stream().map(candidate -> {
            Set<LocationRole> candidateRoles = new LinkedHashSet<>();
            for (String role : candidate.roles()) parseRole(role).ifPresent(candidateRoles::add);
            int score = candidateRoles.stream().anyMatch(allowedRoles(rootCause)::contains) ? 100 : 0;
            if (declared != null && candidateRoles.contains(declared)) score += 25;
            if (decision.primaryChunkId() != null && decision.primaryChunkId() == candidate.chunkId()) score += 8;
            for (String token : claim.split("[^\\p{L}\\p{N}_$]+")) {
                if (token.length() >= 4 && candidate.source().toLowerCase(Locale.ROOT).contains(token)) score++;
            }
            return new RankedLocation(candidate, score);
        }).sorted(Comparator.comparingInt(RankedLocation::score).reversed()).toList();
        if (ranked.isEmpty() || ranked.get(0).score() < 100) return Optional.empty();
        if (ranked.size() > 1 && ranked.get(0).score() == ranked.get(1).score()) return Optional.empty();
        LlmGateway.LocationCandidate best = ranked.get(0).candidate();
        String role = best.roles().stream().filter(value -> parseRole(value)
                        .map(allowedRoles(rootCause)::contains).orElse(false))
                .findFirst().orElse(best.roles().isEmpty() ? "UNCLASSIFIED" : best.roles().get(0));
        return Optional.of(new ResolvedPrimary(best.chunkId(),
                new Location(best.startLine(), best.endLine()), role));
    }

    private static String locationFailureReason(LlmGateway.CriticDecision decision, CodeChunk selected,
                                                Set<Long> allowedChunkIds) {
        if (decision.primaryChunkId() == null) return "Critic 未选择最终主证据代码块";
        if (selected == null) return "Critic 选择的代码块不存在";
        if (!allowedChunkIds.contains(selected.getId())) return "Critic 选择的代码块不属于已验证证据范围";
        Optional<Location> explicit = validateExplicit(
                decision.vulnerabilityStartLine(), decision.vulnerabilityEndLine(), selected);
        if (explicit.isEmpty()) return "Critic 返回的行号为空、越界、倒序或范围过大";
        return "Critic 位置未体现与漏洞根因相符的代码角色，且存在多个可能位置";
    }

    private static boolean isJavaChunk(CodeChunk chunk) {
        String type = safe(chunk.getChunkType()).toUpperCase(Locale.ROOT);
        String path = safe(chunk.getFilePath()).toLowerCase(Locale.ROOT);
        return type.contains("JAVA") || path.endsWith(".java");
    }

    private static List<SourceRange> javaSourceRanges(String content, int lineCount) {
        if (!hasText(content)) return List.of();
        try {
            Node body = StaticJavaParser.parseBodyDeclaration(content);
            List<SourceRange> result = new ArrayList<>();
            for (Node node : body.findAll(Node.class)) {
                if (!(node instanceof AnnotationExpr || node instanceof MethodCallExpr
                        || node instanceof AssignExpr || node instanceof VariableDeclarationExpr
                        || node instanceof ExpressionStmt || node instanceof ReturnStmt
                        || node instanceof ThrowStmt)) continue;
                node.getRange().ifPresent(range -> {
                    int start = Math.max(1, Math.min(range.begin.line, lineCount));
                    int end = Math.max(start, Math.min(range.end.line, lineCount));
                    if (end - start + 1 > MAX_VULNERABLE_LINES) end = start;
                    result.add(new SourceRange(start, end));
                });
            }
            return result;
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private static boolean isExecutableCandidate(String sourceLine) {
        String line = safe(sourceLine).strip();
        return !line.isEmpty() && !line.equals("{") && !line.equals("}") && !line.endsWith("{")
                && !line.startsWith("//") && !line.startsWith("/*") && !line.startsWith("*")
                && !line.startsWith("package ") && !line.startsWith("import ");
    }

    private static String source(String[] lines, int relativeStart, int relativeEnd) {
        StringBuilder result = new StringBuilder();
        for (int line = relativeStart; line <= relativeEnd && line <= lines.length; line++) {
            if (!result.isEmpty()) result.append('\n');
            result.append(lines[line - 1]);
        }
        return result.toString().strip();
    }

    // 从结构化字段和审计结论共同确定根因；明确的“注解不生效”事实优先于模型选择的下游位置角色。
    private static RootCause rootCause(LlmGateway.FindingProposal proposal, LlmGateway.CriticDecision decision) {
        String claim = String.join(" ", safe(proposal.title()), safe(proposal.description()),
                safe(decision.reason())).toLowerCase(Locale.ROOT);
        if ((proposal.type() == VulnerabilityType.AUTHORIZATION
                || proposal.type() == VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE)
                && ineffectiveSecurityClaim(claim)) {
            return RootCause.INEFFECTIVE_SECURITY_CONTROL;
        }
        Optional<RootCause> declared = parseRootCause(decision.rootCauseKind())
                .filter(value -> compatible(proposal.type(), value));
        if (declared.isPresent()) return declared.get();
        return switch (proposal.type()) {
            case AUTHORIZATION -> RootCause.MISSING_AUTHORIZATION_CHECK;
            case SENSITIVE_INFORMATION_DISCLOSURE -> RootCause.UNSAFE_DATA_EXPOSURE;
            case SQL_INJECTION -> RootCause.UNSAFE_QUERY;
            case STORED_XSS -> RootCause.UNSAFE_OUTPUT;
            case VALIDATION_BYPASS -> RootCause.MISSING_VALIDATION;
        };
    }

    private static boolean compatible(VulnerabilityType type, RootCause rootCause) {
        return switch (type) {
            case AUTHORIZATION -> rootCause == RootCause.INEFFECTIVE_SECURITY_CONTROL
                    || rootCause == RootCause.MISSING_AUTHORIZATION_CHECK;
            case SENSITIVE_INFORMATION_DISCLOSURE -> rootCause == RootCause.INEFFECTIVE_SECURITY_CONTROL
                    || rootCause == RootCause.MISSING_AUTHORIZATION_CHECK
                    || rootCause == RootCause.UNSAFE_DATA_EXPOSURE
                    || rootCause == RootCause.HARDCODED_SECRET;
            case SQL_INJECTION -> rootCause == RootCause.UNSAFE_QUERY;
            case STORED_XSS -> rootCause == RootCause.UNSAFE_OUTPUT;
            case VALIDATION_BYPASS -> rootCause == RootCause.MISSING_VALIDATION;
        };
    }

    private static boolean ineffectiveSecurityClaim(String claim) {
        boolean negative = containsAny(claim, "未启用", "没有启用", "未开启", "缺少", "缺失", "不生效",
                "未生效", "失效", "disabled", "not enabled", "missing", "ineffective");
        boolean methodSecurity = containsAny(claim, "enablemethodsecurity", "enableglobalmethodsecurity",
                "方法级安全", "方法安全", "preauthorize", "postauthorize", "secured", "rolesallowed");
        return negative && methodSecurity;
    }

    private static Optional<RootCause> parseRootCause(String value) {
        try {
            return Optional.of(RootCause.valueOf(normalizeEnum(value)));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    private static Optional<LocationRole> parseRole(String value) {
        try {
            return Optional.of(LocationRole.valueOf(normalizeEnum(value)));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    private static String normalizeEnum(String value) {
        return value == null ? "" : value.strip().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }

    private static Set<LocationRole> allowedRoles(RootCause rootCause) {
        return switch (rootCause) {
            case INEFFECTIVE_SECURITY_CONTROL -> Set.of(
                    LocationRole.SECURITY_BOUNDARY, LocationRole.SECURITY_CONFIGURATION);
            case MISSING_AUTHORIZATION_CHECK -> Set.of(
                    LocationRole.SECURITY_BOUNDARY, LocationRole.DATA_ACCESS,
                    LocationRole.DANGEROUS_OPERATION, LocationRole.BUSINESS_OPERATION);
            case UNSAFE_DATA_EXPOSURE -> Set.of(LocationRole.DATA_ACCESS, LocationRole.DATA_OUTPUT);
            case HARDCODED_SECRET -> Set.of(
                    LocationRole.SECRET_DEFINITION, LocationRole.SECURITY_CONFIGURATION);
            case UNSAFE_QUERY -> Set.of(LocationRole.QUERY, LocationRole.DANGEROUS_OPERATION);
            case MISSING_VALIDATION -> Set.of(LocationRole.VALIDATION,
                    LocationRole.DANGEROUS_OPERATION, LocationRole.BUSINESS_OPERATION);
            case UNSAFE_OUTPUT -> Set.of(LocationRole.DATA_OUTPUT, LocationRole.DANGEROUS_OPERATION);
        };
    }

    private static Set<LocationRole> roles(CodeChunk chunk, Location location) {
        String[] lines = contentLines(chunk);
        int chunkStart = Math.max(1, chunk.getStartLine());
        Set<LocationRole> result = new LinkedHashSet<>();
        for (int line = location.startLine(); line <= location.endLine(); line++) {
            int index = line - chunkStart;
            if (index >= 0 && index < lines.length) result.addAll(roles(lines[index]));
        }
        return result;
    }

    // 只识别能够解释安全影响的明确代码角色，不把任意第一条可执行语句当作最终漏洞位置。
    private static Set<LocationRole> roles(String sourceLine) {
        String line = safe(sourceLine).strip().toLowerCase(Locale.ROOT);
        Set<LocationRole> result = new LinkedHashSet<>();
        if (containsAny(line, "@preauthorize", "@postauthorize", "@secured", "@rolesallowed",
                "hasauthority", "hasrole", "checkpermission", "checkauthorization",
                "assertaccountbelongstouser", "belongstouser", "tenant", "owner")) {
            result.add(LocationRole.SECURITY_BOUNDARY);
        }
        if (containsAny(line, "@enablemethodsecurity", "@enableglobalmethodsecurity", "securityfilterchain",
                "authorizehttprequests", "authorizerequests", "requestmatchers", "antmatchers")) {
            result.add(LocationRole.SECURITY_CONFIGURATION);
        }
        if (looksLikeSecretDefinition(line)) {
            result.add(LocationRole.SECRET_DEFINITION);
            if (containsAny(line, "password", "secret", "private-key", "private_key", "client-secret")) {
                result.add(LocationRole.SECURITY_CONFIGURATION);
            }
        }
        if (containsAny(line, "executequery", "executeupdate", "statement.execute", "createstatement",
                "preparestatement", "jdbctemplate", "createquery", "createnativequery", "${", "select ",
                "insert ", "update ", "delete ")) {
            result.add(LocationRole.QUERY);
        }
        if (containsAny(line, "validate", "isvalid", "verify", "checktoken", "checksignature",
                "captcha", "otp", "signature", "bypass")) {
            result.add(LocationRole.VALIDATION);
        }
        if (containsAny(line, "repository.", "mapper.", "dao.", "findall(", "findby", "selectone(",
                "selectlist(", "queryfor", "entitymanager")) {
            result.add(LocationRole.DATA_ACCESS);
        }
        if (containsAny(line, "return ", "response.", ".body(", "getwriter(", "printwriter",
                "innerhtml", "outerhtml", "document.write", "th:utext", "v-html", "render(")) {
            result.add(LocationRole.DATA_OUTPUT);
        }
        if (containsAny(line, ".delete(", ".deleteby", ".save(", ".update(", ".debit(", ".credit(",
                ".transfer(", ".withdraw(", ".execute(", "executequery", "executeupdate")) {
            result.add(LocationRole.DANGEROUS_OPERATION);
        }
        if (containsAny(line, "amount", "price", "balance", "total", "debit", "credit", "transfer",
                "withdraw", "deposit", "purchase")) {
            result.add(LocationRole.BUSINESS_OPERATION);
        }
        return result;
    }

    private static boolean containsAny(String value, String... markers) {
        for (String marker : markers) {
            if (value.contains(marker)) return true;
        }
        return false;
    }

    private static boolean looksLikeSecretDefinition(String line) {
        boolean assignment = line.contains(":") || line.contains("=");
        return assignment && containsAny(line, "password", "passwd", "pwd", "secret", "api-key", "api_key",
                "apikey", "access-key", "access_key", "private-key", "private_key", "client-secret",
                "client_secret", "access-token", "access_token", "refresh-token", "refresh_token");
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    // 执行 FindingLocationResolver 中的 infer 处理。
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

    // 格式化并输出 formatContext 对应的展示内容。
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

    // 执行 FindingLocationResolver 中的 contentLines 处理。
    private static String[] contentLines(CodeChunk chunk) {
        String content = chunk.getContent() == null ? "" : chunk.getContent();
        return content.split("\\R", -1);
    }

    // 执行 FindingLocationResolver 中的 firstExecutableLine 处理。
    private static int firstExecutableLine(String[] lines) {
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index].strip();
            if (!line.isEmpty() && !line.startsWith("@") && !line.endsWith("{")
                    && !line.equals("}")) return index;
        }
        return 0;
    }

    // 执行 FindingLocationResolver 中的 patterns 处理。
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
                    "execute(");
        };
    }

    // 格式化并输出 formatEvidence 对应的展示内容。
    public static String formatEvidence(LlmGateway.FindingProposal proposal,
                                        java.util.Map<Long, CodeChunk> chunks) {
        return formatEvidence(proposal, chunks, Map.of());
    }

    // 格式化并输出 formatEvidence 对应的展示内容。
    public static String formatEvidence(LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks,
                                        Map<Long, Integer> callSiteLines) {
        return proposal.evidenceChunkIds().stream().distinct().map(chunks::get)
                .filter(java.util.Objects::nonNull)
                .map(chunk -> {
                    boolean primary = chunk.getId().equals(proposal.primaryChunkId());
                    Integer callSiteLine = callSiteLines.get(chunk.getId());
                    Location location = primary ? resolve(proposal, chunk)
                            : validCallSite(callSiteLine, chunk).orElseGet(() ->
                            infer(proposal.type(), proposal.description(), chunk));
                    String label = primary ? "[漏洞位置]" : callSiteLine == null ? "[关联证据]"
                            : chunk.getEndpoint() == null || chunk.getEndpoint().isBlank()
                            ? "[调用链]" : "[调用入口]";
                    return "[CHUNK " + chunk.getId() + "] " + label + " " + chunk.getFilePath() + ":"
                            + location.startLine()
                            + (location.endLine() == location.startLine() ? "" : "-" + location.endLine())
                            + " " + chunk.getSymbolName() + "\n" + formatContext(chunk, location, primary);
                })
                .collect(java.util.stream.Collectors.joining("\n\n"));
    }

    /**
     * 为 Critic 审批生成比最终报告更宽、但仍受预算约束的源码窗口。主证据提供漏洞位置前后各
     * 二十行，关联证据提供调用点或推断位置前后各十二行。所有代码仍然只能来自服务端已经批准
     * 的证据块。
     */
    public static String formatCriticEvidence(
            LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks,
            Set<Long> allowedChunkIds, Map<Long, Integer> callSiteLines) {
        if (proposal == null || chunks == null || chunks.isEmpty()) return "";
        Set<Long> allowed = allowedChunkIds == null ? Set.of() : allowedChunkIds;
        Map<Long, Integer> sites = callSiteLines == null ? Map.of() : callSiteLines;
        LinkedHashSet<Long> orderedIds = new LinkedHashSet<>();
        orderedIds.add(proposal.primaryChunkId());
        orderedIds.addAll(proposal.evidenceChunkIds());
        orderedIds.addAll(allowed);
        orderedIds.removeIf(id -> id == null || !allowed.contains(id) || !chunks.containsKey(id));

        StringBuilder result = new StringBuilder();
        for (Long chunkId : orderedIds) {
            CodeChunk chunk = chunks.get(chunkId);
            boolean primary = chunkId.equals(proposal.primaryChunkId());
            Integer callSiteLine = sites.get(chunkId);
            Location location = primary ? resolve(proposal, chunk)
                    : validCallSite(callSiteLine, chunk).orElseGet(() ->
                    infer(proposal.type(), proposal.description(), chunk));
            String label = primary ? "PRIMARY_CONTEXT" : callSiteLine == null
                    ? "RELATED_EVIDENCE" : chunk.getEndpoint() == null || chunk.getEndpoint().isBlank()
                    ? "CALL_CHAIN_EVIDENCE" : "ENTRY_EVIDENCE";
            String code = formatCriticContext(chunk, location,
                    primary ? CRITIC_PRIMARY_CONTEXT_LINES : CRITIC_RELATED_CONTEXT_LINES,
                    primary ? CRITIC_PRIMARY_MAX_CHARS : CRITIC_RELATED_MAX_CHARS);
            String section = "[CRITIC_" + label + "] CHUNK_ID=" + chunk.getId() + " | "
                    + chunk.getFilePath() + ":" + chunk.getStartLine() + "-" + chunk.getEndLine()
                    + " | " + chunk.getSymbolName() + "\n<UNTRUSTED_CODE>\n"
                    + code + "\n</UNTRUSTED_CODE>";
            if (!appendCriticSection(result, section)) break;
        }
        return result.toString();
    }

    private static String formatCriticContext(CodeChunk chunk, Location location,
                                              int contextLines, int maxChars) {
        String[] lines = contentLines(chunk);
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = chunkStart + Math.max(0, lines.length - 1);
        StringBuilder result = new StringBuilder();
        int first = Math.max(chunkStart, location.startLine() - contextLines);
        int last = Math.min(chunkEnd, location.endLine() + contextLines);
        for (int lineNumber = first; lineNumber <= last; lineNumber++) {
            int index = lineNumber - chunkStart;
            if (index < 0 || index >= lines.length) continue;
            boolean marked = lineNumber >= location.startLine() && lineNumber <= location.endLine();
            String numbered = (marked ? ">>> " : "    ")
                    + String.format(Locale.ROOT, "%5d | ", lineNumber) + lines[index] + '\n';
            if (result.length() + numbered.length() > maxChars) break;
            result.append(numbered);
        }
        return result.toString().stripTrailing();
    }

    private static boolean appendCriticSection(StringBuilder result, String section) {
        String separator = result.isEmpty() ? "" : "\n\n";
        int remaining = CRITIC_TOTAL_MAX_CHARS - result.length() - separator.length();
        if (remaining <= 0) return false;
        result.append(separator);
        if (section.length() <= remaining) {
            result.append(section);
            return true;
        }
        String marker = "\n... [CRITIC_CONTEXT_TRUNCATED] ...";
        int contentLength = Math.max(0, remaining - marker.length());
        result.append(section, 0, Math.min(section.length(), contentLength));
        if (remaining >= marker.length()) result.append(marker);
        return false;
    }

    // 执行 FindingLocationResolver 中的 validCallSite 处理。
    private static Optional<Location> validCallSite(Integer line, CodeChunk chunk) {
        return validateExplicit(line, line, chunk);
    }

    // 封装 Location 使用的不可变结构化数据。
    public record Location(int startLine, int endLine) {
    }

    // 保存通过根因和代码角色双重校验后的最终主位置。
    public record ResolvedPrimary(long chunkId, Location location, String locationRole) {
    }

    // 表达位置解析结果，避免把“定位失败”错误转换为“漏洞被否决”。
    public record LocationResolution(LocationStatus status, Optional<ResolvedPrimary> resolved, String reason) {
        public LocationResolution {
            resolved = resolved == null ? Optional.empty() : resolved;
            reason = reason == null ? "" : reason;
        }

        private static LocationResolution unresolved(String reason) {
            return new LocationResolution(LocationStatus.UNRESOLVED, Optional.empty(), reason);
        }
    }

    public enum LocationStatus {
        EXACT, NORMALIZED, REPAIRED, UNRESOLVED
    }

    private record ResolvedCandidate(long chunkId, Location location, LocationRole role, int score) {
    }

    private record SourceRange(int start, int end) {
    }

    private record RankedLocation(LlmGateway.LocationCandidate candidate, int score) {
    }

    private enum RootCause {
        INEFFECTIVE_SECURITY_CONTROL,
        MISSING_AUTHORIZATION_CHECK,
        UNSAFE_DATA_EXPOSURE,
        HARDCODED_SECRET,
        UNSAFE_QUERY,
        MISSING_VALIDATION,
        UNSAFE_OUTPUT
    }

    private enum LocationRole {
        SECURITY_BOUNDARY,
        SECURITY_CONFIGURATION,
        QUERY,
        VALIDATION,
        DATA_ACCESS,
        DATA_OUTPUT,
        SECRET_DEFINITION,
        DANGEROUS_OPERATION,
        BUSINESS_OPERATION
    }
}
