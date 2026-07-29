package com.deepaudit.semantic;

import com.deepaudit.domain.ChunkChangeType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import com.deepaudit.source.AuditSourceFilter;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// 负责 IncrementalSemanticDiffService 对应的业务编排和处理。
@Slf4j
@Service
@RequiredArgsConstructor
public class IncrementalSemanticDiffService {
    private static final int MAX_METHOD_CONTENT_CHARS = 100_000;
    private static final Set<String> SECURITY_ANNOTATIONS = Set.of(
            "preauthorize", "postauthorize", "secured", "rolesallowed", "permitall", "denyall");
    private static final Set<String> SECURITY_GUARD_CALLS = Set.of(
            "checkpermission", "checkrole", "haspermission", "hasrole", "hasauthority",
            "checklogin", "checkowner", "checktenant", "isallowed", "authorize", "verifytoken",
            "verifysignature", "validatepermission");

    private final SemanticMethodChangeMapper changeMapper;

    // 同时解析 Base 与 Target 的方法快照，形成稳定方法映射并把语义变化回填到 Target Chunk。
    public Summary analyze(UUID taskId, Path baseRoot, Path targetRoot, List<CodeChunk> targetChunks,
                           List<GitFileChange> fileChanges) throws IOException {
        MethodIndex base = index(baseRoot);
        MethodIndex target = index(targetRoot);
        Map<String, String> targetPathByBasePath = targetPathMapping(fileChanges);
        Map<String, String> basePathByTargetPath = fileChanges.stream()
                .filter(change -> change.getOldPath() != null && change.getNewPath() != null)
                .collect(Collectors.toMap(GitFileChange::getNewPath, GitFileChange::getOldPath,
                        (left, right) -> left, LinkedHashMap::new));
        Map<String, String> changeTypeByBasePath = fileChanges.stream()
                .filter(change -> change.getOldPath() != null)
                .collect(Collectors.toMap(GitFileChange::getOldPath, GitFileChange::getChangeType,
                        (left, right) -> left, LinkedHashMap::new));
        Map<String, String> changeTypeByTargetPath = fileChanges.stream()
                .filter(change -> change.getNewPath() != null)
                .collect(Collectors.toMap(GitFileChange::getNewPath, GitFileChange::getChangeType,
                        (left, right) -> left, LinkedHashMap::new));
        Set<String> changedBasePaths = fileChanges.stream().map(GitFileChange::getOldPath)
                .filter(java.util.Objects::nonNull).collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> changedTargetPaths = fileChanges.stream().map(GitFileChange::getNewPath)
                .filter(java.util.Objects::nonNull).collect(Collectors.toCollection(LinkedHashSet::new));

        List<SemanticMethodChange> changes = new ArrayList<>();
        Set<MethodSnapshot> pairedBase = new HashSet<>();
        Set<MethodSnapshot> pairedTarget = new HashSet<>();
        Map<String, List<MethodSnapshot>> targetBySignature = target.methods.stream()
                .collect(Collectors.groupingBy(MethodSnapshot::stableSignature,
                        LinkedHashMap::new, Collectors.toList()));

        // 完整类名、方法名和参数类型一致时优先建立精确对应，文件移动不会破坏方法身份。
        for (MethodSnapshot before : base.methods) {
            MethodSnapshot after = targetBySignature.getOrDefault(before.stableSignature(), List.of()).stream()
                    .filter(candidate -> !pairedTarget.contains(candidate))
                    .min(Comparator.comparingInt(candidate -> pathPreference(before, candidate, targetPathByBasePath)))
                    .orElse(null);
            if (after == null) continue;
            pairedBase.add(before);
            pairedTarget.add(after);
            classifyPair(taskId, before, after, changes, targetChunks, false);
        }

        // 对未精确匹配的方法按重命名路径、所属类型、方法名、位置和方法体相似度识别签名变化。
        List<MethodSnapshot> unmatchedTargets = target.methods.stream()
                .filter(method -> !pairedTarget.contains(method)).toList();
        for (MethodSnapshot before : base.methods.stream()
                .filter(method -> !pairedBase.contains(method))
                .sorted(Comparator.comparing(MethodSnapshot::path).thenComparingInt(MethodSnapshot::startLine))
                .toList()) {
            if (!changedBasePaths.contains(before.path())) continue;
            MethodSnapshot after = unmatchedTargets.stream()
                    .filter(candidate -> !pairedTarget.contains(candidate))
                    .filter(candidate -> changedTargetPaths.contains(candidate.path()))
                    .map(candidate -> new ScoredPair(candidate,
                            signatureChangeScore(before, candidate, targetPathByBasePath)))
                    .filter(candidate -> candidate.score() >= 70)
                    .max(Comparator.comparingInt(ScoredPair::score)
                            .thenComparing(candidate -> candidate.method().stableSignature()))
                    .map(ScoredPair::method).orElse(null);
            if (after == null) continue;
            pairedBase.add(before);
            pairedTarget.add(after);
            classifyPair(taskId, before, after, changes, targetChunks, true);
        }

        // 只有 Git 变化文件中的未配对方法才视为新增或删除，避免解析失败污染其他文件。
        for (MethodSnapshot after : target.methods) {
            if (pairedTarget.contains(after) || !changedTargetPaths.contains(after.path())) continue;
            String basePath = basePathByTargetPath.get(after.path());
            if (!"ADD".equals(changeTypeByTargetPath.get(after.path()))
                    && (basePath == null || !base.parsedFiles.contains(basePath))) continue;
            record(taskId, SemanticChangeKind.METHOD_ADDED, null, after,
                    "Target 新增方法 " + after.stableSignature(), changes, targetChunks);
        }
        for (MethodSnapshot before : base.methods) {
            if (pairedBase.contains(before) || !changedBasePaths.contains(before.path())) continue;
            String mappedTargetPath = targetPathByBasePath.get(before.path());
            if (!"DELETE".equals(changeTypeByBasePath.get(before.path()))
                    && (mappedTargetPath == null || !target.parsedFiles.contains(mappedTargetPath))) continue;
            record(taskId, SemanticChangeKind.METHOD_DELETED, before, null, mappedTargetPath,
                    "Base 方法在 Target 中不存在 " + before.stableSignature(), changes, targetChunks);
        }

        changeMapper.deleteByTaskId(taskId);
        for (int start = 0; start < changes.size(); start += 200) {
            changeMapper.insertBatch(changes.subList(start, Math.min(start + 200, changes.size())));
        }
        Summary summary = Summary.from(base.methods.size(), target.methods.size(), changes);
        log.info("任务 {} 方法语义差异完成：baseMethods={}，targetMethods={}，{}",
                taskId, base.methods.size(), target.methods.size(), summary.description());
        return summary;
    }

    // 执行 IncrementalSemanticDiffService 中的 classifyPair 处理。
    private void classifyPair(UUID taskId, MethodSnapshot before, MethodSnapshot after,
                              List<SemanticMethodChange> changes, List<CodeChunk> targetChunks,
                              boolean signatureChangedByMatching) {
        boolean signatureChanged = signatureChangedByMatching
                || !before.declarationFingerprint().equals(after.declarationFingerprint());
        if (signatureChanged) {
            record(taskId, SemanticChangeKind.SIGNATURE_CHANGED, before, after,
                    "方法签名变化：" + before.declarationFingerprint() + " -> "
                            + after.declarationFingerprint(), changes, targetChunks);
        }
        if (!before.bodyFingerprint().equals(after.bodyFingerprint())) {
            record(taskId, SemanticChangeKind.METHOD_MODIFIED, before, after,
                    "方法实现发生变化（同时覆盖仅删除 Target 行的变更）", changes, targetChunks);
        }
        Set<String> addedGuards = new LinkedHashSet<>(after.guards());
        addedGuards.removeAll(before.guards());
        if (!addedGuards.isEmpty()) {
            record(taskId, SemanticChangeKind.GUARD_ADDED, before, after,
                    "新增安全 Guard：" + String.join("；", addedGuards), changes, targetChunks);
        }
        Set<String> removedGuards = new LinkedHashSet<>(before.guards());
        removedGuards.removeAll(after.guards());
        if (!removedGuards.isEmpty()) {
            record(taskId, SemanticChangeKind.GUARD_REMOVED, before, after,
                    "删除安全 Guard：" + String.join("；", removedGuards), changes, targetChunks);
        }
    }

    // 执行 IncrementalSemanticDiffService 中的 record 处理。
    private void record(UUID taskId, SemanticChangeKind kind, MethodSnapshot before,
                        MethodSnapshot after, String details, List<SemanticMethodChange> changes,
                        List<CodeChunk> targetChunks) {
        record(taskId, kind, before, after, after == null ? null : after.path(), details, changes, targetChunks);
    }

    // 执行 IncrementalSemanticDiffService 中的 record 处理。
    private void record(UUID taskId, SemanticChangeKind kind, MethodSnapshot before,
                        MethodSnapshot after, String targetPath, String details,
                        List<SemanticMethodChange> changes, List<CodeChunk> targetChunks) {
        SemanticMethodChange change = new SemanticMethodChange(taskId, kind,
                after == null ? before.name() : after.name(), before == null ? null : before.path(),
                targetPath, before == null ? null : before.stableSignature(),
                after == null ? null : after.stableSignature(), before == null ? null : before.startLine(),
                before == null ? null : before.endLine(), after == null ? null : after.startLine(),
                after == null ? null : after.endLine(), before == null ? "" : before.source(),
                after == null ? "" : after.source(), details);
        changes.add(change);
        if (after != null) markTargetChunk(after, before, kind, targetChunks);
    }

    // 执行 IncrementalSemanticDiffService 中的 markTargetChunk 处理。
    private void markTargetChunk(MethodSnapshot after, MethodSnapshot before, SemanticChangeKind kind,
                                 List<CodeChunk> targetChunks) {
        CodeChunk chunk = targetChunks.stream()
                .filter(candidate -> "JAVA_METHOD".equals(candidate.getChunkType()))
                .filter(candidate -> after.path().equals(candidate.getFilePath()))
                .filter(candidate -> after.startLine() >= candidate.getStartLine()
                        && after.startLine() <= candidate.getEndLine())
                .min(Comparator.comparingInt(candidate -> Math.abs(candidate.getStartLine() - after.startLine())))
                .orElse(null);
        if (chunk == null) return;
        if (kind == SemanticChangeKind.METHOD_ADDED) {
            chunk.setChangeType(ChunkChangeType.ADDED);
        } else if (chunk.getChangeType() != ChunkChangeType.ADDED) {
            chunk.setChangeType(ChunkChangeType.MODIFIED);
        }
        chunk.setAnalysisScope(com.deepaudit.domain.AnalysisScope.CHANGED);
        if (before != null) chunk.setBaseContent(truncate(before.source(), MAX_METHOD_CONTENT_CHARS));
    }

    // 执行 IncrementalSemanticDiffService 中的 index 处理。
    private MethodIndex index(Path root) throws IOException {
        JavaParser parser = new JavaParser(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));
        List<MethodSnapshot> methods = new ArrayList<>();
        Set<String> parsedFiles = new LinkedHashSet<>();
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path file : paths.filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> AuditSourceFilter.shouldAnalyze(root, path)).toList()) {
                String relative = normalized(root.relativize(file));
                try {
                    String source = Files.readString(file, StandardCharsets.UTF_8);
                    CompilationUnit unit = parser.parse(source).getResult().orElse(null);
                    if (unit == null) continue;
                    parsedFiles.add(relative);
                    String[] lines = source.split("\\R", -1);
                    for (TypeDeclaration<?> declaration : unit.findAll(TypeDeclaration.class)) {
                        String owner = declaration.getFullyQualifiedName()
                                .orElseGet(() -> fallbackOwner(unit, declaration));
                        for (MethodDeclaration method : declaration.getMethods()) {
                            if (method.getParentNode().orElse(null) != declaration) continue;
                            if (method.getAnnotations().stream().map(annotation -> annotation.getNameAsString())
                                    .anyMatch(AuditSourceFilter::isTestMethodAnnotation)) continue;
                            int start = line(method);
                            int end = endLine(method);
                            String methodSource = sourceLines(lines, start, end);
                            methods.add(new MethodSnapshot(relative, owner, method.getNameAsString(),
                                    stableSignature(owner, method), normalize(method.getDeclarationAsString(false, false, true)),
                                    canonicalBody(method), start, end, truncate(methodSource, MAX_METHOD_CONTENT_CHARS),
                                    guards(method), method.getParameters().size()));
                        }
                    }
                } catch (RuntimeException exception) {
                    log.warn("无法建立增量方法快照: {}", file, exception);
                }
            }
        }
        methods.sort(Comparator.comparing(MethodSnapshot::path).thenComparingInt(MethodSnapshot::startLine));
        return new MethodIndex(List.copyOf(methods), Set.copyOf(parsedFiles));
    }

    // 执行 IncrementalSemanticDiffService 中的 signatureChangeScore 处理。
    private int signatureChangeScore(MethodSnapshot before, MethodSnapshot after,
                                     Map<String, String> targetPathByBasePath) {
        if (!before.name().equals(after.name())) return 0;
        boolean sameOwner = before.owner().equals(after.owner());
        boolean mappedPath = after.path().equals(targetPathByBasePath.get(before.path()));
        if (!sameOwner && !mappedPath) return 0;
        int score = 20;
        if (sameOwner) score += 45;
        if (mappedPath) score += 35;
        if (simpleOwner(before.owner()).equals(simpleOwner(after.owner()))) score += 10;
        if (Math.abs(before.parameterCount() - after.parameterCount()) <= 1) score += 5;
        if (Math.abs(before.startLine() - after.startLine()) <= 20) score += 5;
        score += Math.min(20, (int) Math.round(tokenSimilarity(before.bodyFingerprint(), after.bodyFingerprint()) * 20));
        return Math.min(score, 100);
    }

    // 转换并返回 tokenSimilarity 对应的数据表示。
    private double tokenSimilarity(String left, String right) {
        Set<String> leftTokens = tokens(left);
        Set<String> rightTokens = tokens(right);
        if (leftTokens.isEmpty() && rightTokens.isEmpty()) return 1.0;
        Set<String> intersection = new HashSet<>(leftTokens);
        intersection.retainAll(rightTokens);
        Set<String> union = new HashSet<>(leftTokens);
        union.addAll(rightTokens);
        return union.isEmpty() ? 0 : (double) intersection.size() / union.size();
    }

    // 转换并返回 tokens 对应的数据表示。
    private Set<String> tokens(String value) {
        return Stream.of(value.toLowerCase(Locale.ROOT).split("[^a-z0-9_$]+"))
                .filter(token -> !token.isBlank()).collect(Collectors.toSet());
    }

    // 执行 IncrementalSemanticDiffService 中的 pathPreference 处理。
    private int pathPreference(MethodSnapshot before, MethodSnapshot after,
                               Map<String, String> targetPathByBasePath) {
        if (after.path().equals(targetPathByBasePath.get(before.path()))) return 0;
        if (after.path().equals(before.path())) return 1;
        return 2;
    }

    // 执行 IncrementalSemanticDiffService 中的 targetPathMapping 处理。
    private Map<String, String> targetPathMapping(List<GitFileChange> changes) {
        Map<String, String> result = new HashMap<>();
        for (GitFileChange change : changes) {
            if (change.getOldPath() != null && change.getNewPath() != null) {
                result.put(change.getOldPath(), change.getNewPath());
            }
        }
        return result;
    }

    // 执行 IncrementalSemanticDiffService 中的 guards 处理。
    private Set<String> guards(MethodDeclaration method) {
        Set<String> result = new LinkedHashSet<>();
        method.getAnnotations().stream().filter(annotation -> SECURITY_ANNOTATIONS.contains(
                        annotation.getNameAsString().toLowerCase(Locale.ROOT)))
                .map(annotation -> normalize(annotation.toString())).forEach(result::add);
        method.findAll(MethodCallExpr.class).stream()
                .filter(call -> isGuardCall(call.getNameAsString(), call.toString()))
                .map(call -> normalize(call.toString())).forEach(result::add);
        return Set.copyOf(result);
    }

    // 判断是否满足 isGuardCall 对应的条件。
    private boolean isGuardCall(String name, String expression) {
        String value = (name + " " + expression).toLowerCase(Locale.ROOT);
        return SECURITY_GUARD_CALLS.stream().anyMatch(value::contains)
                || value.contains("stputil.check") || value.contains("subject.checkpermission")
                || value.contains("subject.hasrole");
    }

    // 判断是否满足 canonicalBody 对应的条件。
    private String canonicalBody(MethodDeclaration method) {
        MethodDeclaration copy = method.clone();
        copy.getAllContainedComments().forEach(comment -> comment.remove());
        copy.removeComment();
        String annotations = copy.getAnnotations().stream().map(Node::toString).sorted()
                .collect(Collectors.joining(" "));
        return normalize(annotations + " " + copy.getBody().map(Node::toString).orElse(";"));
    }

    // 执行 IncrementalSemanticDiffService 中的 stableSignature 处理。
    private String stableSignature(String owner, MethodDeclaration method) {
        return owner + "." + method.getNameAsString() + "(" + method.getParameters().stream()
                .map(parameter -> normalizeType(parameter.getTypeAsString()))
                .collect(Collectors.joining(",")) + ")";
    }

    // 规范化 normalizeType 对应的输入。
    private String normalizeType(String value) {
        return value.replaceAll("\\s+", "").replace("...", "[]");
    }

    // 执行 IncrementalSemanticDiffService 中的 fallbackOwner 处理。
    private String fallbackOwner(CompilationUnit unit, TypeDeclaration<?> declaration) {
        String packageName = unit.getPackageDeclaration().map(value -> value.getNameAsString() + ".").orElse("");
        List<String> owners = new ArrayList<>();
        Node current = declaration;
        while (current instanceof TypeDeclaration<?> type) {
            owners.add(0, type.getNameAsString());
            current = type.getParentNode().orElse(null);
        }
        return packageName + String.join(".", owners);
    }

    // 执行 IncrementalSemanticDiffService 中的 sourceLines 处理。
    private String sourceLines(String[] lines, int startLine, int endLine) {
        StringBuilder result = new StringBuilder();
        for (int index = Math.max(0, startLine - 1); index < Math.min(lines.length, endLine); index++) {
            if (!result.isEmpty()) result.append('\n');
            result.append(lines[index]);
        }
        return result.toString();
    }

    // 执行 IncrementalSemanticDiffService 中的 simpleOwner 处理。
    private String simpleOwner(String value) {
        int dot = value.lastIndexOf('.');
        return dot < 0 ? value : value.substring(dot + 1);
    }

    // 规范化 normalize 对应的输入。
    private String normalize(String value) {
        return value == null ? "" : value.replaceAll("\\s+", " ").strip();
    }

    // 规范化 normalized 对应的输入。
    private String normalized(Path path) {
        return path.toString().replace('\\', '/');
    }

    // 执行 IncrementalSemanticDiffService 中的 line 处理。
    private int line(Node node) {
        return node.getBegin().map(position -> position.line).orElse(1);
    }

    // 执行 IncrementalSemanticDiffService 中的 endLine 处理。
    private int endLine(Node node) {
        return node.getEnd().map(position -> position.line).orElse(line(node));
    }

    // 执行 IncrementalSemanticDiffService 中的 truncate 处理。
    private String truncate(String value, int maxLength) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), maxLength));
    }

    // 封装 MethodIndex 使用的不可变结构化数据。
    private record MethodIndex(List<MethodSnapshot> methods, Set<String> parsedFiles) {
    }

    // 封装 MethodSnapshot 使用的不可变结构化数据。
    private record MethodSnapshot(String path, String owner, String name, String stableSignature,
                                  String declarationFingerprint, String bodyFingerprint,
                                  int startLine, int endLine, String source, Set<String> guards,
                                  int parameterCount) {
    }

    // 封装 ScoredPair 使用的不可变结构化数据。
    private record ScoredPair(MethodSnapshot method, int score) {
    }

    // 封装 Summary 使用的不可变结构化数据。
    public record Summary(int baseMethodCount, int targetMethodCount,
                          Map<SemanticChangeKind, Long> counts) {
        // 执行 Summary 中的 from 处理。
        private static Summary from(int baseMethods, int targetMethods,
                                    List<SemanticMethodChange> changes) {
            Map<SemanticChangeKind, Long> counts = new EnumMap<>(SemanticChangeKind.class);
            for (SemanticMethodChange change : changes) {
                counts.merge(change.getChangeKind(), 1L, Long::sum);
            }
            return new Summary(baseMethods, targetMethods, Map.copyOf(counts));
        }

        // 执行 Summary 中的 description 处理。
        public String description() {
            if (counts.isEmpty()) return "未发现方法级语义变化";
            return counts.entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .collect(Collectors.joining("，"));
        }
    }
}
