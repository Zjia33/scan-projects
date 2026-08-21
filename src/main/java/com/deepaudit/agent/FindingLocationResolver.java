package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.FindingLocationKind;
import com.deepaudit.domain.VulnerabilityType;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.IfStmt;
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
import java.util.TreeSet;

public final class FindingLocationResolver {
    private static final int CONTEXT_LINES = 4;
    private static final int CRITIC_PRIMARY_CONTEXT_LINES = 20;
    private static final int CRITIC_RELATED_CONTEXT_LINES = 12;
    private static final int CRITIC_PRIMARY_MAX_CHARS = 6_000;
    private static final int CRITIC_RELATED_MAX_CHARS = 4_000;
    private static final int CRITIC_TOTAL_MAX_CHARS = 20_000;
    private static final int CRITIC_LOCATION_CONTEXT_LINES = 2;
    private static final int CRITIC_LOCATION_MAX_RANGE_LINES = 12;
    private static final int CRITIC_LOCATION_MAX_LINE_CHARS = 800;
    private static final int MAX_VULNERABLE_LINES = 5;

    private FindingLocationResolver() {
    }

    public static Location resolve(LlmGateway.FindingProposal proposal, CodeChunk chunk) {
        return validateExplicit(proposal.vulnerabilityStartLine(), proposal.vulnerabilityEndLine(), chunk)
                .filter(location -> hasLocationCode(chunk, location))
                .orElseGet(() -> infer(proposal.type(), proposal.title() + " " + proposal.description(), chunk));
    }

    // 专业 Agent 必须显式提交真实可执行代码范围；允许范围超过 5 行。
    public static ExplicitLocationValidation validateProfessionalExplicit(
            Integer proposedStart, Integer proposedEnd, CodeChunk chunk) {
        if (chunk == null) {
            return ExplicitLocationValidation.invalid("primaryChunkId 对应的代码块不存在");
        }
        if (proposedStart == null || proposedEnd == null) {
            return ExplicitLocationValidation.invalid(
                    "vulnerabilityStartLine 和 vulnerabilityEndLine 不能为空");
        }
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = Math.max(chunkStart, chunk.getEndLine());
        if (proposedStart > proposedEnd) {
            return ExplicitLocationValidation.invalid(
                    "vulnerabilityStartLine 不能大于 vulnerabilityEndLine");
        }
        if (proposedStart < chunkStart || proposedEnd > chunkEnd) {
            return ExplicitLocationValidation.invalid(
                    "漏洞行号 " + proposedStart + "-" + proposedEnd
                            + " 超出 primary 代码块范围 " + chunkStart + "-" + chunkEnd);
        }
        Location location = new Location(proposedStart, proposedEnd);
        if (!hasExecutableCode(chunk, location)) {
            return ExplicitLocationValidation.invalid("选定范围内没有有效可执行代码");
        }
        return ExplicitLocationValidation.valid(location);
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
                locationCandidates(proposal.type(), chunks, allowedChunkIds)).resolved();
    }

    /**
     * 分级解析 Critic 位置。模型声明的根因、角色和行号是定位提示；只有服务器生成的候选 ID、
     * 真实代码块边界以及验证过的证据范围属于硬约束。
     */
    public static LocationResolution resolveCriticLocation(
            LlmGateway.FindingProposal proposal, LlmGateway.CriticDecision decision,
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds,
            List<LlmGateway.LocationCandidate> candidates) {
        RootCause rootCause = rootCause(proposal, decision);
        if (hasText(decision.locationCandidateId())) {
            Optional<ResolvedPrimary> selected = resolveCandidate(
                    decision.locationCandidateId(), candidates, proposal, decision, chunks, allowedChunkIds);
            if (selected.isPresent()) {
                return new LocationResolution(LocationStatus.EXACT, selected,
                        "Critic 选择的位置候选已通过源码类型、证据范围和根因角色校验");
            }
        }

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
                Set<CandidatePurpose> actualPurposes = purposes(
                        rootCause, actualRoles, selected, sourceAt(selected, explicit.get()));
                CandidatePurpose acceptedPurpose = preferredPrimaryPurpose(rootCause, actualPurposes).orElse(null);
                if (acceptedRole != null && acceptedPurpose != null) {
                    return new LocationResolution(LocationStatus.EXACT,
                            Optional.of(new ResolvedPrimary(selected.getId(), explicit.get(), acceptedRole.name(),
                                    acceptedPurpose.name())),
                            "Critic 行号位于真实证据块内并符合根因代码角色");
                }
            }
        }

        Optional<ResolvedPrimary> normalized = bestDeterministicCandidate(
                proposal, decision, rootCause, candidates, chunks, allowedChunkIds);
        if (normalized.isPresent()) {
            return new LocationResolution(LocationStatus.NORMALIZED, normalized,
                    "Critic 原始位置不精确，已根据根因和真实源码候选确定性重定位");
        }
        return LocationResolution.unresolved(locationFailureReason(decision, selected, allowedChunkIds));
    }

    // 从验证过的证据代码块生成稳定候选 ID；Java 优先使用 AST 表达式，其他文本使用真实源码行。
    public static List<LlmGateway.LocationCandidate> locationCandidates(
            VulnerabilityType vulnerabilityType, Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        List<LlmGateway.LocationCandidate> result = new ArrayList<>();
        for (Long chunkId : allowedChunkIds) {
            CodeChunk chunk = chunks.get(chunkId);
            if (chunk == null) continue;
            String[] lines = contentLines(chunk);
            String[] codeLines = codeLines(lines);
            Map<String, SourceRange> ranges = new LinkedHashMap<>();
            if (isJavaChunk(chunk)) {
                for (SourceRange range : javaSourceRanges(chunk.getContent(), lines.length)) {
                    ranges.putIfAbsent(range.start() + ":" + range.end(), range);
                }
            }
            for (int index = 0; index < lines.length; index++) {
                if (!roles(codeLines[index]).isEmpty()) {
                    int relative = index + 1;
                    ranges.putIfAbsent(relative + ":" + relative, new SourceRange(relative, relative));
                }
            }
            if (ranges.isEmpty()) {
                for (int index = 0; index < lines.length; index++) {
                    if (isExecutableCandidate(codeLines[index])
                            && !isStructuralDeclaration(codeLines[index])) {
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
                String code = source(codeLines, relative.start(), relative.end());
                if (isStructuralDeclaration(code)) continue;
                Location location = new Location(start, end);
                Set<LocationRole> actualRoles = new LinkedHashSet<>(roles(chunk, location));
                actualRoles.addAll(roles(code));
                List<String> detectedRoles = actualRoles.stream().map(Enum::name).sorted().toList();
                List<String> purposes = purposes(vulnerabilityType, actualRoles, chunk, code)
                        .stream().map(Enum::name).sorted().toList();
                String candidateId = chunk.getId() + ":" + start + "-" + end;
                result.add(new LlmGateway.LocationCandidate(candidateId, chunk.getId(), chunk.getFilePath(),
                        chunk.getSymbolName(), start, end, source, detectedRoles, purposes,
                        chunk.getAnalysisScope() == null ? "" : chunk.getAnalysisScope().name()));
            }
        }
        return List.copyOf(result);
    }

    // 候选 ID 只是索引，仍需根据当前源码、证据范围和漏洞根因重新校验，不能直接信任候选携带的角色。
    public static Optional<ResolvedPrimary> resolveCandidate(
            String candidateId, List<LlmGateway.LocationCandidate> candidates,
            LlmGateway.FindingProposal proposal, LlmGateway.CriticDecision decision,
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        if (!hasText(candidateId)) return Optional.empty();
        return candidates.stream().filter(candidate -> candidate.candidateId().equals(candidateId))
                .findFirst().flatMap(candidate -> validateCandidate(
                        candidate, rootCause(proposal, decision),
                        chunks, allowedChunkIds))
                .map(ValidatedLocation::resolved);
    }

    // 对“安全控制未启用/不生效”选择真正失效的注解或安全配置行，拒绝把下游数据读取当作根因。
    private static Optional<ResolvedPrimary> ineffectiveSecurityBoundary(
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        ResolvedCandidate best = null;
        for (Long chunkId : allowedChunkIds) {
            CodeChunk chunk = chunks.get(chunkId);
            if (chunk == null) continue;
            String[] lines = contentLines(chunk);
            String[] codeLines = codeLines(lines);
            int chunkStart = Math.max(1, chunk.getStartLine());
            for (int index = 0; index < lines.length; index++) {
                Set<LocationRole> lineRoles = roles(codeLines[index]);
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
        return Optional.of(new ResolvedPrimary(best.chunkId(), best.location(), best.role().name(),
                CandidatePurpose.ROOT_CAUSE.name()));
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
            RootCause rootCause, List<LlmGateway.LocationCandidate> candidates,
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        LocationRole declared = parseRole(decision.locationRole()).orElse(null);
        String claim = String.join(" ", safe(proposal.title()), safe(proposal.description()),
                safe(decision.reason())).toLowerCase(Locale.ROOT);
        List<RankedLocation> ranked = candidates.stream()
                .map(candidate -> validateCandidate(
                        candidate, rootCause, chunks, allowedChunkIds))
                .flatMap(Optional::stream)
                .map(validated -> {
                    int score = validated.purposes().contains(CandidatePurpose.ROOT_CAUSE) ? 1_000 : 700;
                    String candidateSource = validated.candidate().source().strip();
                    if (candidateSource.endsWith(";") || (candidateSource.startsWith("if")
                            && candidateSource.endsWith("}"))) score += 20;
                    if (declared != null && validated.roles().contains(declared)) score += 25;
                    if (decision.primaryChunkId() != null
                            && decision.primaryChunkId() == validated.candidate().chunkId()) score += 8;
                    for (String token : claim.split("[^\\p{L}\\p{N}_$]+")) {
                        if (token.length() >= 4 && validated.candidate().source()
                                .toLowerCase(Locale.ROOT).contains(token)) score++;
                    }
                    return new RankedLocation(validated, score);
                }).sorted(Comparator.comparingInt(RankedLocation::score).reversed()).toList();
        if (ranked.isEmpty() || ranked.get(0).score() < 700) return Optional.empty();
        if (ranked.size() > 1 && ranked.get(0).score() == ranked.get(1).score()) return Optional.empty();
        return Optional.of(ranked.get(0).validated().resolved());
    }

    private static Optional<ValidatedLocation> validateCandidate(
            LlmGateway.LocationCandidate candidate, RootCause rootCause,
            Map<Long, CodeChunk> chunks, Set<Long> allowedChunkIds) {
        if (candidate == null || !allowedChunkIds.contains(candidate.chunkId())) return Optional.empty();
        CodeChunk chunk = chunks.get(candidate.chunkId());
        if (chunk == null) return Optional.empty();
        Optional<Location> location = validateExplicit(candidate.startLine(), candidate.endLine(), chunk);
        if (location.isEmpty()) return Optional.empty();
        if (!hasLocationCode(chunk, location.get()) || !matchesCurrentSource(candidate, chunk)) {
            return Optional.empty();
        }
        Set<LocationRole> actualRoles = roles(chunk, location.get());
        actualRoles.addAll(roles(candidate.source()));
        LocationRole acceptedRole = actualRoles.stream()
                .filter(allowedRoles(rootCause)::contains).findFirst().orElse(null);
        Set<CandidatePurpose> actualPurposes = purposes(rootCause, actualRoles, chunk, candidate.source());
        CandidatePurpose acceptedPurpose = preferredPrimaryPurpose(rootCause, actualPurposes).orElse(null);
        if (acceptedRole == null || acceptedPurpose == null) return Optional.empty();
        return Optional.of(new ValidatedLocation(candidate,
                new ResolvedPrimary(chunk.getId(), location.get(), acceptedRole.name(), acceptedPurpose.name()),
                actualRoles, actualPurposes));
    }

    private static boolean matchesCurrentSource(LlmGateway.LocationCandidate candidate, CodeChunk chunk) {
        String[] lines = contentLines(chunk);
        int relativeStart = candidate.startLine() - Math.max(1, chunk.getStartLine()) + 1;
        int relativeEnd = candidate.endLine() - Math.max(1, chunk.getStartLine()) + 1;
        return source(lines, relativeStart, relativeEnd).equals(safe(candidate.source()).strip());
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
        Node parsed;
        try {
            parsed = StaticJavaParser.parseBodyDeclaration(content);
        } catch (RuntimeException bodyDeclarationFailure) {
            try {
                parsed = StaticJavaParser.parse(content);
            } catch (RuntimeException compilationUnitFailure) {
                return List.of();
            }
        }
        List<SourceRange> result = new ArrayList<>();
        for (Node node : parsed.findAll(Node.class)) {
            if (!(node instanceof AnnotationExpr || node instanceof MethodCallExpr
                    || node instanceof AssignExpr || node instanceof VariableDeclarationExpr
                    || node instanceof ExpressionStmt || node instanceof IfStmt || node instanceof ReturnStmt
                    || node instanceof ThrowStmt)) continue;
            node.getRange().ifPresent(range -> {
                int start = Math.max(1, Math.min(range.begin.line, lineCount));
                int end = Math.max(start, Math.min(range.end.line, lineCount));
                if (end - start + 1 > MAX_VULNERABLE_LINES) end = start;
                result.add(new SourceRange(start, end));
            });
        }
        return result;
    }

    private static boolean isExecutableCandidate(String sourceLine) {
        String line = safe(sourceLine).strip();
        return isLocationCandidateLine(line) && !line.startsWith("@");
    }

    // JAVA_CHANGE 可能是无法独立解析的文件片段；兜底时排除字段、类型和构造器参数等结构声明。
    // 硬编码凭据字段仍是实际漏洞位置，因此保留包含真实赋值的秘密定义。
    private static boolean isStructuralDeclaration(String sourceLine) {
        String line = safe(sourceLine).strip();
        if (line.isEmpty()) return true;
        if (line.matches("(?s)^this\\s*\\.\\s*[A-Za-z_$][\\w$]*\\s*=.*;$")
                && !looksLikeSecretDefinition(line)) return true;
        try {
            Node declaration = StaticJavaParser.parseBodyDeclaration(line);
            if (declaration instanceof FieldDeclaration field) {
                if (looksLikeSecretDefinition(line)) return false;
                boolean explicitField = field.isPublic() || field.isProtected() || field.isPrivate()
                        || field.isStatic() || field.isTransient() || field.isVolatile();
                return explicitField || !line.contains("=");
            }
            if (declaration instanceof TypeDeclaration<?> || declaration instanceof ConstructorDeclaration) {
                return true;
            }
        } catch (RuntimeException ignored) {
            // Partial changed ranges often cannot be parsed as a body declaration.
        }
        if (!line.contains("=") && (line.endsWith(",") || line.endsWith(")"))) {
            String parameter = line.substring(0, line.length() - 1).strip();
            try {
                StaticJavaParser.parseParameter(parameter);
                return true;
            } catch (RuntimeException ignored) {
                // The line is an expression rather than a constructor/method parameter.
            }
        }
        return false;
    }

    private static boolean isLocationCandidateLine(String sourceLine) {
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
                    LocationRole.DATA_OUTPUT, LocationRole.DANGEROUS_OPERATION,
                    LocationRole.BUSINESS_OPERATION);
            case UNSAFE_DATA_EXPOSURE -> Set.of(LocationRole.DATA_ACCESS, LocationRole.DATA_OUTPUT);
            case HARDCODED_SECRET -> Set.of(
                    LocationRole.SECRET_DEFINITION, LocationRole.SECURITY_CONFIGURATION);
            case UNSAFE_QUERY -> Set.of(LocationRole.QUERY_CONSTRUCTION, LocationRole.QUERY_EXECUTION,
                    LocationRole.QUERY, LocationRole.DANGEROUS_OPERATION);
            case MISSING_VALIDATION -> Set.of(LocationRole.VALIDATION,
                    LocationRole.DANGEROUS_OPERATION, LocationRole.BUSINESS_OPERATION);
            case UNSAFE_OUTPUT -> Set.of(LocationRole.DATA_OUTPUT, LocationRole.DANGEROUS_OPERATION);
        };
    }

    private static RootCause defaultRootCause(VulnerabilityType type) {
        if (type == null) return RootCause.UNSAFE_QUERY;
        return switch (type) {
            case AUTHORIZATION -> RootCause.MISSING_AUTHORIZATION_CHECK;
            case SENSITIVE_INFORMATION_DISCLOSURE -> RootCause.UNSAFE_DATA_EXPOSURE;
            case SQL_INJECTION -> RootCause.UNSAFE_QUERY;
            case STORED_XSS -> RootCause.UNSAFE_OUTPUT;
            case VALIDATION_BYPASS -> RootCause.MISSING_VALIDATION;
        };
    }

    private static Set<CandidatePurpose> purposes(RootCause rootCause, Set<LocationRole> roles,
                                                   CodeChunk chunk, String source) {
        Set<CandidatePurpose> result = new LinkedHashSet<>();
        boolean endpoint = chunk != null && hasText(chunk.getEndpoint());
        boolean delegatingEntry = endpoint && looksLikeDelegatingEntry(source);
        if (endpoint) result.add(CandidatePurpose.ENTRY);
        switch (rootCause) {
            case INEFFECTIVE_SECURITY_CONTROL -> {
                if (roles.contains(LocationRole.SECURITY_BOUNDARY)
                        || roles.contains(LocationRole.SECURITY_CONFIGURATION)) {
                    result.add(CandidatePurpose.ROOT_CAUSE);
                }
            }
            case MISSING_AUTHORIZATION_CHECK -> {
                if (roles.contains(LocationRole.SECURITY_BOUNDARY)) result.add(CandidatePurpose.ROOT_CAUSE);
                if (!delegatingEntry && intersects(roles, LocationRole.DATA_ACCESS, LocationRole.DATA_OUTPUT,
                        LocationRole.DANGEROUS_OPERATION, LocationRole.BUSINESS_OPERATION)) {
                    result.add(CandidatePurpose.RESPONSIBILITY_ANCHOR);
                }
            }
            case UNSAFE_DATA_EXPOSURE -> {
                if (roles.contains(LocationRole.SECRET_DEFINITION)
                        || (!delegatingEntry && roles.contains(LocationRole.DATA_OUTPUT))) {
                    result.add(CandidatePurpose.ROOT_CAUSE);
                }
                if (roles.contains(LocationRole.DATA_ACCESS)) result.add(CandidatePurpose.IMPACT);
            }
            case HARDCODED_SECRET -> {
                if (roles.contains(LocationRole.SECRET_DEFINITION)) result.add(CandidatePurpose.ROOT_CAUSE);
            }
            case UNSAFE_QUERY -> {
                if (roles.contains(LocationRole.QUERY_CONSTRUCTION)) result.add(CandidatePurpose.ROOT_CAUSE);
                if (roles.contains(LocationRole.QUERY_EXECUTION)) result.add(CandidatePurpose.IMPACT);
            }
            case MISSING_VALIDATION -> {
                if (roles.contains(LocationRole.VALIDATION)) result.add(CandidatePurpose.ROOT_CAUSE);
                if (!delegatingEntry && intersects(roles, LocationRole.DANGEROUS_OPERATION,
                        LocationRole.BUSINESS_OPERATION, LocationRole.DATA_ACCESS)) {
                    result.add(CandidatePurpose.RESPONSIBILITY_ANCHOR);
                }
            }
            case UNSAFE_OUTPUT -> {
                if (roles.contains(LocationRole.UNSAFE_RENDER)) result.add(CandidatePurpose.ROOT_CAUSE);
                if (roles.contains(LocationRole.DATA_OUTPUT) || roles.contains(LocationRole.DATA_ACCESS)
                        || roles.contains(LocationRole.DANGEROUS_OPERATION)) {
                    result.add(CandidatePurpose.IMPACT);
                }
            }
        }
        if (result.isEmpty()) result.add(CandidatePurpose.SUPPORTING);
        return result;
    }

    private static Set<CandidatePurpose> purposes(VulnerabilityType type, Set<LocationRole> roles,
                                                   CodeChunk chunk, String source) {
        Set<CandidatePurpose> result = new LinkedHashSet<>();
        for (RootCause rootCause : compatibleRootCauses(type)) {
            result.addAll(purposes(rootCause, roles, chunk, source));
        }
        if (result.size() > 1) result.remove(CandidatePurpose.SUPPORTING);
        return result;
    }

    private static Set<RootCause> compatibleRootCauses(VulnerabilityType type) {
        if (type == null) return Set.of(RootCause.UNSAFE_QUERY);
        return switch (type) {
            case AUTHORIZATION -> Set.of(
                    RootCause.INEFFECTIVE_SECURITY_CONTROL, RootCause.MISSING_AUTHORIZATION_CHECK);
            case SENSITIVE_INFORMATION_DISCLOSURE -> Set.of(
                    RootCause.INEFFECTIVE_SECURITY_CONTROL, RootCause.MISSING_AUTHORIZATION_CHECK,
                    RootCause.UNSAFE_DATA_EXPOSURE, RootCause.HARDCODED_SECRET);
            case SQL_INJECTION -> Set.of(RootCause.UNSAFE_QUERY);
            case STORED_XSS -> Set.of(RootCause.UNSAFE_OUTPUT);
            case VALIDATION_BYPASS -> Set.of(RootCause.MISSING_VALIDATION);
        };
    }

    private static Optional<CandidatePurpose> preferredPrimaryPurpose(
            RootCause rootCause, Set<CandidatePurpose> purposes) {
        if (purposes.contains(CandidatePurpose.ROOT_CAUSE)) return Optional.of(CandidatePurpose.ROOT_CAUSE);
        if ((rootCause == RootCause.MISSING_AUTHORIZATION_CHECK || rootCause == RootCause.MISSING_VALIDATION)
                && purposes.contains(CandidatePurpose.RESPONSIBILITY_ANCHOR)) {
            return Optional.of(CandidatePurpose.RESPONSIBILITY_ANCHOR);
        }
        return Optional.empty();
    }

    private static boolean intersects(Set<LocationRole> roles, LocationRole... expected) {
        for (LocationRole role : expected) if (roles.contains(role)) return true;
        return false;
    }

    private static Set<LocationRole> roles(CodeChunk chunk, Location location) {
        String[] lines = codeLines(contentLines(chunk));
        int chunkStart = Math.max(1, chunk.getStartLine());
        Set<LocationRole> result = new LinkedHashSet<>();
        for (int line = location.startLine(); line <= location.endLine(); line++) {
            int index = line - chunkStart;
            if (index >= 0 && index < lines.length) result.addAll(roles(lines[index]));
        }
        result.addAll(roles(source(lines,
                location.startLine() - chunkStart + 1,
                location.endLine() - chunkStart + 1)));
        return result;
    }

    private static String sourceAt(CodeChunk chunk, Location location) {
        String[] lines = contentLines(chunk);
        int chunkStart = Math.max(1, chunk.getStartLine());
        return source(lines, location.startLine() - chunkStart + 1,
                location.endLine() - chunkStart + 1);
    }

    // 只识别能够解释安全影响的明确代码角色，不把任意第一条可执行语句当作最终漏洞位置。
    private static Set<LocationRole> roles(String sourceLine) {
        String line = safe(sourceLine).strip().toLowerCase(Locale.ROOT);
        if (!isLocationCandidateLine(line)) return Set.of();
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
        if (looksLikeUnsafeQueryConstruction(line)) {
            result.add(LocationRole.QUERY_CONSTRUCTION);
            result.add(LocationRole.QUERY);
        }
        if (containsAny(line, "executequery", "executeupdate", "statement.execute", "createstatement",
                "preparestatement", "jdbctemplate", "queryfor", "createquery", "createnativequery")) {
            result.add(LocationRole.QUERY_EXECUTION);
            result.add(LocationRole.QUERY);
        }
        if (looksLikeValidationDecision(line)) {
            result.add(LocationRole.VALIDATION);
        }
        if (containsAny(line, "repository.", "mapper.", "dao.", "findall(", "findby", "selectone(",
                "selectlist(", "queryfor", "entitymanager")) {
            result.add(LocationRole.DATA_ACCESS);
        }
        if (containsAny(line, "return ", "response.", ".body(", "getwriter(", ".print(", ".println(",
                ".write(", "system.out.print", "system.err.print", "innerhtml", "outerhtml",
                "document.write", "th:utext", "v-html", "render(") || looksLikeLogWrite(line)) {
            result.add(LocationRole.DATA_OUTPUT);
        }
        if (looksLikeUnsafeRender(line)) result.add(LocationRole.UNSAFE_RENDER);
        if (containsAny(line, ".delete(", ".deleteby", ".save(", ".update(", ".debit(", ".credit(",
                ".transfer(", ".withdraw(", ".execute(", "executequery", "executeupdate")) {
            result.add(LocationRole.DANGEROUS_OPERATION);
        }
        if (line.matches(".*\\b[a-z_$][a-z0-9_$]*(?:port|gateway|client)\\s*\\.\\s*"
                + "(?:apply|submit|send|publish|write|execute|commit)\\s*\\(.*")) {
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

    private static boolean looksLikeLogWrite(String line) {
        return line.matches(".*\\b(?:log|logger|[a-z_$][a-z0-9_$]*logger)\\s*\\.\\s*"
                + "(?:trace|debug|info|warn|error)\\s*\\(.*");
    }

    private static boolean looksLikeUnsafeQueryConstruction(String source) {
        String value = safe(source).toLowerCase(Locale.ROOT);
        if (value.contains("${")) return true;
        boolean queryContext = containsAny(value, "sql", "select ", " from ", " where ", " like ",
                " order by ", " group by ", " having ", " union ", "insert ", "update ", "delete ");
        if (!queryContext) return false;
        boolean dynamicAppend = value.matches("(?s).*\\.append\\(\\s*(?![\"']).+?");
        boolean dynamicConcatenation = value.matches("(?s).*[\"']\\s*\\+\\s*[a-z_$].*")
                || value.matches("(?s).*\\+\\s*(?:request|input|param|value|name|id|field)[a-z0-9_$.()]*.*");
        return dynamicAppend || dynamicConcatenation || containsAny(value, "string.format(", ".formatted(");
    }

    private static boolean looksLikeValidationDecision(String source) {
        String value = safe(source).toLowerCase(Locale.ROOT);
        if (containsAny(value, "validate", "isvalid", "verify", "checktoken", "checksignature",
                "captcha", "otp", "signature", "bypass")) return true;
        return value.contains("if") && containsAny(value, "throw ", "return false", "return null")
                && containsAny(value, "request", "input", "amount", "price", "quantity", "token",
                "field", "value", "parameter");
    }

    private static boolean looksLikeUnsafeRender(String source) {
        String value = safe(source).toLowerCase(Locale.ROOT);
        return containsAny(value, "innerhtml", "outerhtml", "document.write", "th:utext", "v-html",
                "dangerouslysetinnerhtml", "html(", "mediatype.text_html", "text/html");
    }

    private static boolean looksLikeDelegatingEntry(String source) {
        String value = safe(source).strip().toLowerCase(Locale.ROOT);
        return (value.startsWith("return ") || value.matches("(?s)^[a-z_$][a-z0-9_$]*\\..*"))
                && containsAny(value, "service.", "usecase.", "handler.", "facade.", "gateway.", "client.");
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public static Location infer(VulnerabilityType type, String description, CodeChunk chunk) {
        String[] lines = codeLines(contentLines(chunk));
        List<String> patterns = patterns(type);
        int bestIndex = -1;
        int bestScore = 0;
        String normalizedDescription = description == null ? "" : description.toLowerCase(Locale.ROOT);
        for (int index = 0; index < lines.length; index++) {
            if (!isLocationCandidateLine(lines[index])) continue;
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

    private static boolean hasLocationCode(CodeChunk chunk, Location location) {
        String[] lines = codeLines(contentLines(chunk));
        int chunkStart = Math.max(1, chunk.getStartLine());
        for (int line = location.startLine(); line <= location.endLine(); line++) {
            int index = line - chunkStart;
            if (index >= 0 && index < lines.length && isLocationCandidateLine(lines[index])) return true;
        }
        return false;
    }

    private static boolean hasExecutableCode(CodeChunk chunk, Location location) {
        String[] lines = codeLines(contentLines(chunk));
        int chunkStart = Math.max(1, chunk.getStartLine());
        for (int line = location.startLine(); line <= location.endLine(); line++) {
            int index = line - chunkStart;
            if (index >= 0 && index < lines.length
                    && isExecutableCandidate(lines[index])
                    && !isStructuralDeclaration(lines[index])) {
                return true;
            }
        }
        return false;
    }

    // 在词法识别前剔除行注释和跨行块注释，避免注释中的 API 名称污染安全角色。
    private static String[] codeLines(String[] sourceLines) {
        String[] result = new String[sourceLines.length];
        boolean inBlockComment = false;
        boolean inTextBlock = false;
        for (int lineIndex = 0; lineIndex < sourceLines.length; lineIndex++) {
            String sourceLine = sourceLines[lineIndex];
            StringBuilder code = new StringBuilder();
            boolean inString = false;
            boolean inCharacter = false;
            boolean escaped = false;
            for (int index = 0; index < sourceLine.length(); index++) {
                char current = sourceLine.charAt(index);
                char next = index + 1 < sourceLine.length() ? sourceLine.charAt(index + 1) : '\0';
                if (inBlockComment) {
                    if (current == '*' && next == '/') {
                        inBlockComment = false;
                        index++;
                    }
                    continue;
                }
                if (!inString && !inCharacter && current == '"' && next == '"'
                        && index + 2 < sourceLine.length() && sourceLine.charAt(index + 2) == '"') {
                    inTextBlock = !inTextBlock;
                    code.append("\"\"\"");
                    index += 2;
                    continue;
                }
                if (!inTextBlock && !inString && !inCharacter && current == '/' && next == '/') break;
                if (!inTextBlock && !inString && !inCharacter && current == '/' && next == '*') {
                    inBlockComment = true;
                    index++;
                    continue;
                }
                code.append(current);
                if (inTextBlock) continue;
                if (escaped) {
                    escaped = false;
                } else if ((inString || inCharacter) && current == '\\') {
                    escaped = true;
                } else if (!inCharacter && current == '"') {
                    inString = !inString;
                } else if (!inString && current == '\'') {
                    inCharacter = !inCharacter;
                }
            }
            result[lineIndex] = code.toString();
        }
        return result;
    }

    private static int firstExecutableLine(String[] lines) {
        for (int index = 0; index < lines.length; index++) {
            if (isExecutableCandidate(lines[index])) return index;
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
                    "execute(");
        };
    }

    public static String formatEvidence(LlmGateway.FindingProposal proposal,
                                        java.util.Map<Long, CodeChunk> chunks) {
        return formatEvidence(proposal, chunks, Map.of(), FindingLocationKind.ROOT_CAUSE, null);
    }

    public static String formatEvidence(LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks,
                                        Map<Long, Integer> callSiteLines) {
        return formatEvidence(proposal, chunks, callSiteLines, FindingLocationKind.ROOT_CAUSE, null);
    }

    public static String formatEvidence(LlmGateway.FindingProposal proposal, Map<Long, CodeChunk> chunks,
                                        Map<Long, Integer> callSiteLines,
                                        FindingLocationKind primaryLocationKind,
                                        String rootCauseKind) {
        return proposal.evidenceChunkIds().stream().distinct().map(chunks::get)
                .filter(java.util.Objects::nonNull)
                .map(chunk -> {
                    boolean primary = chunk.getId().equals(proposal.primaryChunkId());
                    Integer callSiteLine = callSiteLines.get(chunk.getId());
                    Location location = primary ? validateProfessionalExplicit(
                            proposal.vulnerabilityStartLine(), proposal.vulnerabilityEndLine(), chunk)
                            .location().orElseGet(() -> resolve(proposal, chunk))
                            : validCallSite(callSiteLine, chunk).orElseGet(() ->
                            infer(proposal.type(), proposal.description(), chunk));
                    String label;
                    if (primary) {
                        label = primaryLocationKind == FindingLocationKind.RESPONSIBILITY_ANCHOR
                                ? "[责任锚点]" : "[漏洞根因]";
                    } else if (callSiteLine != null) {
                        label = chunk.getEndpoint() == null || chunk.getEndpoint().isBlank()
                                ? "[调用链]" : "[调用入口]";
                    } else {
                        String purpose = evidencePurpose(proposal.type(), rootCauseKind, chunk, location);
                        label = "ROOT_CAUSE".equals(purpose) ? "[根因证据]"
                                : "IMPACT".equals(purpose) ? "[影响位置]" : "[关联证据]";
                    }
                    return "[CHUNK " + chunk.getId() + "] " + label + " " + chunk.getFilePath() + ":"
                            + location.startLine()
                            + (location.endLine() == location.startLine() ? "" : "-" + location.endLine())
                            + " " + chunk.getSymbolName() + "\n" + formatContext(chunk, location, primary);
                })
                .collect(java.util.stream.Collectors.joining("\n\n"));
    }

    public static String evidencePurpose(VulnerabilityType type, CodeChunk chunk, Location location) {
        return evidencePurpose(type, null, chunk, location);
    }

    public static String evidencePurpose(VulnerabilityType type, String rootCauseKind,
                                         CodeChunk chunk, Location location) {
        Set<LocationRole> detected = roles(chunk, location);
        RootCause rootCause = parseRootCause(rootCauseKind).filter(value -> compatible(type, value))
                .orElseGet(() -> defaultRootCause(type));
        return purposes(rootCause, detected, chunk, sourceAt(chunk, location)).stream()
                .filter(purpose -> purpose != CandidatePurpose.SUPPORTING)
                .sorted(Comparator.comparingInt(FindingLocationResolver::purposePriority).reversed())
                .map(Enum::name).findFirst().orElse(CandidatePurpose.SUPPORTING.name());
    }

    private static int purposePriority(CandidatePurpose purpose) {
        return switch (purpose) {
            case ROOT_CAUSE -> 5;
            case RESPONSIBILITY_ANCHOR -> 4;
            case IMPACT -> 3;
            case ENTRY -> 2;
            case SUPPORTING -> 1;
        };
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

    /**
     * 将待模型选择的定位候选与源码窗口打包。文件和符号在每个代码块头部只出现一次，
     * 同一源码行在一个证据包内也只出现一次；只有实际进入字符预算的候选才会返回给 Critic。
     */
    public static CriticEvidencePackage formatCriticEvidencePackage(
            Map<Long, CodeChunk> chunks, List<LlmGateway.LocationCandidate> selectedCandidates) {
        if (chunks == null || chunks.isEmpty() || selectedCandidates == null || selectedCandidates.isEmpty()) {
            return new CriticEvidencePackage("", List.of(), Set.of());
        }
        List<LlmGateway.LocationCandidate> included = new ArrayList<>();
        String evidence = "";
        for (LlmGateway.LocationCandidate candidate : selectedCandidates) {
            if (!validEvidenceCandidate(candidate, chunks.get(candidate == null ? null : candidate.chunkId()))) {
                continue;
            }
            List<LlmGateway.LocationCandidate> trial = new ArrayList<>(included);
            trial.add(candidate);
            String rendered = renderLocationEvidence(chunks, trial);
            if (rendered.length() > CRITIC_TOTAL_MAX_CHARS) continue;
            included.add(candidate);
            evidence = rendered;
        }
        LinkedHashSet<Long> chunkIds = included.stream().map(LlmGateway.LocationCandidate::chunkId)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        return new CriticEvidencePackage(evidence, included, chunkIds);
    }

    private static boolean validEvidenceCandidate(LlmGateway.LocationCandidate candidate, CodeChunk chunk) {
        if (candidate == null || chunk == null || candidate.endLine() < candidate.startLine()) return false;
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = chunkStart + Math.max(0, contentLines(chunk).length - 1);
        return candidate.startLine() >= chunkStart && candidate.endLine() <= chunkEnd;
    }

    private static String renderLocationEvidence(
            Map<Long, CodeChunk> chunks, List<LlmGateway.LocationCandidate> candidates) {
        Map<Long, List<LlmGateway.LocationCandidate>> byChunk = new LinkedHashMap<>();
        for (LlmGateway.LocationCandidate candidate : candidates) {
            byChunk.computeIfAbsent(candidate.chunkId(), ignored -> new ArrayList<>()).add(candidate);
        }
        StringBuilder result = new StringBuilder();
        for (Map.Entry<Long, List<LlmGateway.LocationCandidate>> entry : byChunk.entrySet()) {
            CodeChunk chunk = chunks.get(entry.getKey());
            if (chunk == null) continue;
            if (!result.isEmpty()) result.append("\n\n");
            result.append("[CRITIC_LOCATION_EVIDENCE] CHUNK_ID=").append(chunk.getId())
                    .append(" | ").append(safe(chunk.getFilePath())).append(":")
                    .append(chunk.getStartLine()).append("-").append(chunk.getEndLine())
                    .append(" | ").append(safe(chunk.getSymbolName())).append('\n');
            for (LlmGateway.LocationCandidate candidate : entry.getValue()) {
                result.append("[LOCATION_REF] candidateId=").append(candidate.candidateId())
                        .append(" | lines=").append(candidate.startLine()).append("-")
                        .append(candidate.endLine()).append(" | roles=").append(candidate.roles())
                        .append(" | purposes=").append(candidate.purposes())
                        .append(" | scope=").append(candidate.analysisScope()).append('\n');
            }
            result.append("<UNTRUSTED_CODE>\n")
                    .append(formatLocationSource(chunk, entry.getValue()))
                    .append("\n</UNTRUSTED_CODE>");
        }
        return result.toString();
    }

    private static String formatLocationSource(
            CodeChunk chunk, List<LlmGateway.LocationCandidate> candidates) {
        String[] lines = contentLines(chunk);
        int chunkStart = Math.max(1, chunk.getStartLine());
        int chunkEnd = chunkStart + Math.max(0, lines.length - 1);
        TreeSet<Integer> visibleLines = new TreeSet<>();
        for (LlmGateway.LocationCandidate candidate : candidates) {
            int rangeLines = candidate.endLine() - candidate.startLine() + 1;
            if (rangeLines <= CRITIC_LOCATION_MAX_RANGE_LINES) {
                addLineRange(visibleLines,
                        Math.max(chunkStart, candidate.startLine() - CRITIC_LOCATION_CONTEXT_LINES),
                        Math.min(chunkEnd, candidate.endLine() + CRITIC_LOCATION_CONTEXT_LINES));
            } else {
                addLineRange(visibleLines, Math.max(chunkStart, candidate.startLine() - 2),
                        Math.min(chunkEnd, candidate.startLine() + 5));
                addLineRange(visibleLines, Math.max(chunkStart, candidate.endLine() - 5),
                        Math.min(chunkEnd, candidate.endLine() + 2));
            }
        }
        StringBuilder result = new StringBuilder();
        Integer previous = null;
        for (Integer lineNumber : visibleLines) {
            if (previous != null && lineNumber > previous + 1) {
                result.append("    ... [SOURCE_LINES_OMITTED] ...\n");
            }
            int index = lineNumber - chunkStart;
            if (index < 0 || index >= lines.length) continue;
            String sourceLine = lines[index];
            if (sourceLine.length() > CRITIC_LOCATION_MAX_LINE_CHARS) {
                sourceLine = sourceLine.substring(0, CRITIC_LOCATION_MAX_LINE_CHARS)
                        + " ... [LINE_TRUNCATED]";
            }
            boolean candidateLine = candidates.stream().anyMatch(candidate ->
                    lineNumber >= candidate.startLine() && lineNumber <= candidate.endLine());
            result.append(candidateLine ? ">>> " : "    ")
                    .append(String.format(Locale.ROOT, "%5d | ", lineNumber))
                    .append(sourceLine).append('\n');
            previous = lineNumber;
        }
        return result.toString().stripTrailing();
    }

    private static void addLineRange(Set<Integer> target, int start, int end) {
        for (int line = start; line <= end; line++) target.add(line);
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

    private static Optional<Location> validCallSite(Integer line, CodeChunk chunk) {
        return validateExplicit(line, line, chunk);
    }

    public record Location(int startLine, int endLine) {
    }

    public record ExplicitLocationValidation(Optional<Location> location, String reason) {
        private static ExplicitLocationValidation valid(Location location) {
            return new ExplicitLocationValidation(Optional.of(location), "");
        }

        private static ExplicitLocationValidation invalid(String reason) {
            return new ExplicitLocationValidation(Optional.empty(), reason);
        }

        public boolean valid() {
            return location.isPresent();
        }
    }

    public record CriticEvidencePackage(String text, List<LlmGateway.LocationCandidate> candidates,
                                        Set<Long> chunkIds) {
        public CriticEvidencePackage {
            text = text == null ? "" : text;
            candidates = candidates == null ? List.of() : List.copyOf(candidates);
            chunkIds = chunkIds == null ? Set.of() : Set.copyOf(chunkIds);
        }
    }

    // 保存通过根因和代码角色双重校验后的最终主位置。
    public record ResolvedPrimary(long chunkId, Location location, String locationRole, String locationKind) {
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

    private record ValidatedLocation(LlmGateway.LocationCandidate candidate,
                                     ResolvedPrimary resolved, Set<LocationRole> roles,
                                     Set<CandidatePurpose> purposes) {
    }

    private record RankedLocation(ValidatedLocation validated, int score) {
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
        QUERY_CONSTRUCTION,
        QUERY_EXECUTION,
        VALIDATION,
        DATA_ACCESS,
        DATA_OUTPUT,
        UNSAFE_RENDER,
        SECRET_DEFINITION,
        DANGEROUS_OPERATION,
        BUSINESS_OPERATION
    }

    private enum CandidatePurpose {
        ROOT_CAUSE,
        RESPONSIBILITY_ANCHOR,
        IMPACT,
        ENTRY,
        SUPPORTING
    }
}
