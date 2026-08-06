package com.deepaudit.recon;

import com.deepaudit.codegraph.CodeGraphClient;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.ChunkChangeType;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.source.AuditFileRole;
import com.deepaudit.source.AuditSourceFilter;
import com.deepaudit.semantic.IncrementalSemanticDiffService;
import com.deepaudit.util.TimingDetailLog;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParseProblemException;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

@Slf4j
@Service
public class ReconService {

    private static final long MAX_SOURCE_FILE_BYTES = 2L * 1024L * 1024L;
    private static final int MAX_TEXT_CHUNK_CHARS = 12_000;
    private static final int MAX_TEXT_CHUNK_LINES = 160;
    private static final int MAX_FRAMEWORK_FILE_CHARS = 24_000;
    private static final int MAX_FRAMEWORK_CONTEXT_CHARS = 120_000;
    private static final int MAX_FRAMEWORK_FILES = 40;
    private final CodeChunkMapper chunkMapper;
    private final IncrementalSemanticDiffService incrementalSemanticDiffService;
    private final ProjectTechnologyDetector technologyDetector = new ProjectTechnologyDetector();
    private final ProjectStructureProfiler structureProfiler = new ProjectStructureProfiler();

    public ReconService(CodeChunkMapper chunkMapper) {
        this(chunkMapper, null);
    }

    @Autowired
    public ReconService(CodeChunkMapper chunkMapper,
                        IncrementalSemanticDiffService incrementalSemanticDiffService) {
        this.chunkMapper = chunkMapper;
        this.incrementalSemanticDiffService = incrementalSemanticDiffService;
        StaticJavaParser.setConfiguration(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));
    }

    // 扫描受支持源码，生成代码块和项目技术栈摘要。
    // 建立 Target 代码块，同时保留 Base/Target 差异和完整目标上下文。
    @Transactional
    public ReconSummary buildIndex(UUID taskId, Path root, Path baseRoot,
                                   List<GitFileChange> changes) throws IOException {
        // 重建前清空旧代码块，确保同一任务的索引可重复生成。
        if (changes == null || changes.isEmpty()) {
            throw new IllegalArgumentException("增量索引必须提供 Git 变更清单");
        }
        chunkMapper.deleteByTaskId(taskId);
        long startedAt = System.nanoTime();
        List<CodeChunk> chunks = new ArrayList<>();
        int[] counters = new int[3];
        List<Path> frameworkPaths = frameworkFilePaths(root);
        Stream<Path> changedFileStream = changes.stream().map(GitFileChange::getNewPath)
                .filter(java.util.Objects::nonNull).map(path -> safeResolve(root, path))
                .filter(java.util.Objects::nonNull).distinct();
        try (Stream<Path> paths = changedFileStream) {
            // 只遍历受支持的文本源码，二进制和未知文件不进入模型上下文。
            paths.filter(Files::isRegularFile)
                    .filter(path -> AuditSourceFilter.classify(root, path).createChunks())
                    .forEach(path -> indexFile(taskId, root, path, chunks, counters));
        }
        applyIncrementalMetadata(chunks, changes);
        // 增量模式进一步比较 Base/Target 方法快照，覆盖纯删除、签名和安全 Guard 变化。
        if (incrementalSemanticDiffService != null) {
            incrementalSemanticDiffService.analyze(taskId, baseRoot, root, chunks, changes);
        }
        addUncoveredChangedRanges(taskId, root, chunks, changes);
        chunks.removeIf(chunk -> chunk.getAnalysisScope() != AnalysisScope.CHANGED);
        for (int start = 0; start < chunks.size(); start += 500) {
            chunkMapper.insertBatch(chunks.subList(start, Math.min(start + 500, chunks.size())));
        }
        // 独立识别构建工具、框架和安全组件，供 Recon Agent 理解项目背景。
        List<Path> reconFiles = new ArrayList<>(frameworkPaths);
        changes.stream().map(GitFileChange::getNewPath).filter(java.util.Objects::nonNull)
                .map(path -> safeResolve(root, path)).filter(java.util.Objects::nonNull)
                .forEach(reconFiles::add);
        TechnologyProfile technologyProfile = technologyDetector.detect(root, reconFiles);
        // 结构画像只消费变更代码和框架配置，避免 Recon 重复遍历全部业务源码。
        ProjectStructureProfile projectStructure = structureProfiler.profile(root, chunks, reconFiles);
        TimingDetailLog.info("任务 {} 增量初始索引完成：changedFiles={}，changedChunks={}，frameworkFiles={}，"
                        + "elapsedMs={}", taskId, counters[0], chunks.size(), frameworkPaths.size(),
                (System.nanoTime() - startedAt) / 1_000_000);
        return new ReconSummary(counters[0], counters[1], counters[2], chunks.size(),
                technologyProfile, projectStructure, frameworkFiles(root, frameworkPaths));
    }

    // 将调用图扩展得到的代码块提升为深度分析范围。
    public void promoteImpactScope(UUID taskId, Set<Long> impactedChunkIds) {
        List<CodeChunk> chunks = chunkMapper.findByTaskId(taskId);
        List<CodeChunk> promoted = new ArrayList<>();
        for (CodeChunk chunk : chunks) {
            if (chunk.getAnalysisScope() == AnalysisScope.CHANGED) continue;
            if (chunk.getId() != null && impactedChunkIds.contains(chunk.getId())) {
                chunk.setAnalysisScope(AnalysisScope.IMPACTED);
                promoted.add(chunk);
            }
        }
        promoted.forEach(chunkMapper::updateIncrementalMetadata);
    }

    @Transactional
    public int materializeCodeGraphLocations(UUID taskId, Path root,
                                             List<CodeGraphClient.CodeGraphLocation> locations) {
        if (locations == null || locations.isEmpty()) return 0;
        Map<String, List<CodeGraphClient.CodeGraphLocation>> byPath = locations.stream()
                .filter(java.util.Objects::nonNull)
                .filter(location -> location.filePath() != null && !location.filePath().isBlank())
                .collect(java.util.stream.Collectors.groupingBy(
                        location -> normalizePath(location.filePath()), LinkedHashMap::new,
                        java.util.stream.Collectors.toList()));
        List<CodeChunk> existing = chunkMapper.findByTaskId(taskId);
        Set<String> keys = existing.stream().map(this::chunkKey)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        List<CodeChunk> additions = new ArrayList<>();
        for (Map.Entry<String, List<CodeGraphClient.CodeGraphLocation>> entry : byPath.entrySet()) {
            Path file = safeResolve(root, entry.getKey());
            if (file == null || !Files.isRegularFile(file)
                    || !AuditSourceFilter.classify(root, file).createChunks()) continue;
            List<CodeChunk> candidates = new ArrayList<>();
            indexFile(taskId, root, file, candidates, new int[3]);
            for (CodeChunk candidate : candidates) {
                if (!matchesAnyLocation(candidate, entry.getValue()) || !keys.add(chunkKey(candidate))) continue;
                candidate.setAnalysisScope(AnalysisScope.CONTEXT);
                candidate.setChangeType(ChunkChangeType.UNCHANGED);
                candidate.setBaseContent("");
                additions.add(candidate);
            }
        }
        insertChunks(additions);
        TimingDetailLog.info("任务 {} CodeGraph 位置按需物化完成：locations={}，files={}，newChunks={}",
                taskId, locations.size(), byPath.size(), additions.size());
        return additions.size();
    }

    @Transactional
    public int materializeGlobalSecurityContext(UUID taskId, Path root) {
        List<CodeChunk> existing = chunkMapper.findByTaskId(taskId);
        Set<String> keys = existing.stream().map(this::chunkKey)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        List<CodeChunk> additions = new ArrayList<>();
        int selectedFiles = 0;
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path file : paths.filter(Files::isRegularFile)
                    .filter(path -> AuditSourceFilter.classify(root, path).createChunks())
                    .filter(this::globalContextFile).toList()) {
                selectedFiles++;
                List<CodeChunk> candidates = new ArrayList<>();
                indexFile(taskId, root, file, candidates, new int[3]);
                for (CodeChunk candidate : candidates) {
                    if (!keys.add(chunkKey(candidate))) continue;
                    candidate.setAnalysisScope(AnalysisScope.CONTEXT);
                    candidate.setChangeType(ChunkChangeType.UNCHANGED);
                    candidate.setBaseContent("");
                    additions.add(candidate);
                }
            }
        } catch (IOException exception) {
            log.warn("任务 {} 全局安全上下文候选文件收集未完整执行", taskId, exception);
        }
        insertChunks(additions);
        TimingDetailLog.info("任务 {} 全局配置变化上下文按需物化：selectedFiles={}，newChunks={}",
                taskId, selectedFiles, additions.size());
        return additions.size();
    }

    private void insertChunks(List<CodeChunk> chunks) {
        for (int start = 0; start < chunks.size(); start += 500) {
            chunkMapper.insertBatch(chunks.subList(start, Math.min(start + 500, chunks.size())));
        }
    }

    private boolean matchesAnyLocation(CodeChunk chunk,
                                       List<CodeGraphClient.CodeGraphLocation> locations) {
        for (CodeGraphClient.CodeGraphLocation location : locations) {
            if (location.startLine() != null && location.startLine() > 0
                    && location.startLine() >= chunk.getStartLine()
                    && location.startLine() <= chunk.getEndLine()) return true;
            String expected = simpleName(location.name());
            if (!expected.isBlank() && expected.equals(simpleName(chunk.getSymbolName()))) return true;
        }
        return false;
    }

    private String simpleName(String value) {
        if (value == null) return "";
        String name = value.strip();
        int parameters = name.indexOf('(');
        if (parameters >= 0) name = name.substring(0, parameters);
        int separator = Math.max(name.lastIndexOf('#'), Math.max(name.lastIndexOf('.'), name.lastIndexOf(':')));
        return (separator < 0 ? name : name.substring(separator + 1)).toLowerCase(Locale.ROOT);
    }

    private String chunkKey(CodeChunk chunk) {
        return normalizePath(chunk.getFilePath()) + ":" + chunk.getStartLine() + ":" + chunk.getEndLine()
                + ":" + (chunk.getSymbolName() == null ? "" : chunk.getSymbolName());
    }

    private boolean globalContextFile(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        String path = normalizePath(file.toString()).toLowerCase(Locale.ROOT);
        return isFrameworkFile(file) || name.contains("security") || name.contains("controller")
                || name.contains("filter") || name.contains("interceptor") || name.contains("mapper")
                || path.contains("/security/") || path.contains("/controller/")
                || path.contains("/filter/") || path.contains("/interceptor/");
    }

    private void applyIncrementalMetadata(List<CodeChunk> chunks,
                                          List<GitFileChange> changes) {
        Map<String, GitFileChange> byPath = new LinkedHashMap<>();
        for (GitFileChange change : changes) {
            if (change.getNewPath() != null) byPath.put(normalizePath(change.getNewPath()), change);
        }
        for (CodeChunk chunk : chunks) {
            chunk.setAnalysisScope(AnalysisScope.CONTEXT);
            chunk.setChangeType(ChunkChangeType.UNCHANGED);
            chunk.setBaseContent("");
            GitFileChange change = byPath.get(normalizePath(chunk.getFilePath()));
            if (change == null) continue;
            boolean direct = "ADD".equals(change.getChangeType())
                    || overlaps(chunk.getStartLine(), chunk.getEndLine(), change.getNewRanges());
            if (!direct) continue;
            chunk.setChangeType(switch (change.getChangeType()) {
                case "ADD" -> ChunkChangeType.ADDED;
                case "RENAME", "COPY" -> ChunkChangeType.RENAMED;
                default -> ChunkChangeType.MODIFIED;
            });
            chunk.setAnalysisScope(AnalysisScope.CHANGED);
            chunk.setBaseContent(truncateBase(change.getContextText()));
        }
    }

    private void addUncoveredChangedRanges(UUID taskId, Path root, List<CodeChunk> chunks,
                                           List<GitFileChange> changes) {
        for (GitFileChange change : changes) {
            if (change.getNewPath() == null || change.getNewRanges() == null
                    || change.getNewRanges().isBlank()) continue;
            String relativePath = normalizePath(change.getNewPath());
            Path file = safeResolve(root, relativePath);
            if (file == null || !Files.isRegularFile(file)
                    || !AuditSourceFilter.classify(root, file).createChunks()) continue;
            String content;
            try {
                if (Files.size(file) > MAX_SOURCE_FILE_BYTES) continue;
                content = Files.readString(file, StandardCharsets.UTF_8);
            } catch (IOException exception) {
                log.warn("无法读取未被方法块覆盖的变更行: {}", file, exception);
                continue;
            }
            List<LineRange> uncovered = parseRanges(change.getNewRanges());
            if (relativePath.toLowerCase(Locale.ROOT).endsWith(".java")) {
                try {
                    CompilationUnit unit = StaticJavaParser.parse(content);
                    for (MethodDeclaration method : unit.findAll(MethodDeclaration.class).stream()
                            .filter(candidate -> candidate.getAnnotations().stream()
                                    .map(AnnotationExpr::getNameAsString)
                                    .anyMatch(AuditSourceFilter::isTestMethodAnnotation)).toList()) {
                        int start = method.getBegin().map(position -> position.line).orElse(1);
                        int end = method.getEnd().map(position -> position.line).orElse(start);
                        uncovered = subtract(uncovered, start, end);
                    }
                } catch (ParseProblemException ignored) {
                }
            }
            for (CodeChunk chunk : chunks.stream()
                    .filter(candidate -> relativePath.equals(normalizePath(candidate.getFilePath())))
                    .filter(candidate -> candidate.getAnalysisScope() == AnalysisScope.CHANGED).toList()) {
                uncovered = subtract(uncovered, chunk.getStartLine(), chunk.getEndLine());
            }
            for (LineRange range : uncovered) {
                String source = sourceLines(content, range.start(), range.end());
                if (source.isBlank()) continue;
                CodeChunk fallback = new CodeChunk(taskId, relativePath,
                        file.getFileName() + "#changed-lines-" + range.start() + "-" + range.end(), null,
                        range.start(), range.end(), truncate(source), "JAVA_CHANGE", "", "", "");
                fallback.setAnalysisScope(AnalysisScope.CHANGED);
                fallback.setChangeType("ADD".equals(change.getChangeType())
                        ? ChunkChangeType.ADDED : "RENAME".equals(change.getChangeType())
                        || "COPY".equals(change.getChangeType())
                        ? ChunkChangeType.RENAMED : ChunkChangeType.MODIFIED);
                fallback.setBaseContent(truncateBase(change.getContextText()));
                chunks.add(fallback);
            }
        }
    }

    private List<LineRange> parseRanges(String ranges) {
        List<LineRange> result = new ArrayList<>();
        for (String value : ranges.split(",")) {
            String[] parts = value.split(":");
            if (parts.length != 2) continue;
            try {
                int start = Math.max(1, Integer.parseInt(parts[0]));
                int end = Math.max(start, Integer.parseInt(parts[1]));
                result.add(new LineRange(start, end));
            } catch (NumberFormatException ignored) {
            }
        }
        return result;
    }

    private List<LineRange> subtract(List<LineRange> ranges, int coveredStart, int coveredEnd) {
        List<LineRange> result = new ArrayList<>();
        for (LineRange range : ranges) {
            if (coveredEnd < range.start() || coveredStart > range.end()) {
                result.add(range);
                continue;
            }
            if (coveredStart > range.start()) {
                result.add(new LineRange(range.start(), coveredStart - 1));
            }
            if (coveredEnd < range.end()) {
                result.add(new LineRange(coveredEnd + 1, range.end()));
            }
        }
        return result;
    }

    private boolean overlaps(int chunkStart, int chunkEnd, String ranges) {
        if (ranges == null || ranges.isBlank()) return false;
        for (String value : ranges.split(",")) {
            String[] parts = value.split(":");
            if (parts.length != 2) continue;
            try {
                int start = Integer.parseInt(parts[0]);
                int end = Integer.parseInt(parts[1]);
                if (chunkStart <= end && chunkEnd >= start) return true;
            } catch (NumberFormatException ignored) {
            }
        }
        return false;
    }

    // 规范化 normalizePath 对应的输入。
    private String normalizePath(String value) {
        return value == null ? "" : value.replace('\\', '/');
    }

    private String truncateBase(String value) {
        if (value == null) return "";
        return value.substring(0, Math.min(value.length(), 4_000));
    }

    // 根据文件类型选择 Java 方法级解析或通用文本窗口切分。
    private void indexFile(UUID taskId, Path root, Path file, List<CodeChunk> chunks, int[] counters) {
        try {
            if (Files.size(file) > MAX_SOURCE_FILE_BYTES) {
                return;
            }
            // 统一使用 UTF-8 读取，并保存相对于隔离工作区的路径。
            String content = Files.readString(file, StandardCharsets.UTF_8);
            String relativePath = root.relativize(file).toString().replace('\\', '/');
            AuditFileRole role = AuditSourceFilter.classify(relativePath);
            if (!role.createChunks()) return;
            counters[0]++;
            if (role == AuditFileRole.JAVA_SOURCE) {
                indexJava(taskId, relativePath, content, chunks, counters);
            } else {
                indexText(taskId, relativePath, file.getFileName().toString(), content, chunks,
                        "TEXT_" + extension(relativePath).toUpperCase(Locale.ROOT));
            }
        } catch (Exception exception) {
            // 单个编码异常或无法解析的文件不能中断整个扫描任务，但必须留下可诊断记录。
            log.warn("跳过无法建立索引的文件: {}", file, exception);
        }
    }

    // 将可解析 Java 源码切成带接口、参数、注解和调用符号的方法级代码块。
    private void indexJava(UUID taskId, String relativePath, String content,
                           List<CodeChunk> chunks, int[] counters) {
        CompilationUnit unit;
        try {
            // JavaParser 失败时退化为文本分块，避免遗漏仍可审查的源码。
            unit = StaticJavaParser.parse(content);
        } catch (ParseProblemException exception) {
            indexText(taskId, relativePath, relativePath, content, chunks, "JAVA_FILE");
            return;
        }
        String basePath = unit.findFirst(ClassOrInterfaceDeclaration.class)
                .flatMap(type -> mappingPath(type.getAnnotations()))
                .orElse("");
        List<MethodDeclaration> methods = unit.findAll(MethodDeclaration.class);
        if (methods.isEmpty()) {
            indexText(taskId, relativePath, relativePath, content, chunks, "JAVA_FILE");
            return;
        }
        for (MethodDeclaration method : methods) {
            if (method.getAnnotations().stream()
                    .map(AnnotationExpr::getNameAsString)
                    .anyMatch(AuditSourceFilter::isTestMethodAnnotation)) {
                continue;
            }
            int start = method.getBegin().map(position -> position.line).orElse(1);
            int end = method.getEnd().map(position -> position.line).orElse(start);
            String endpoint = mappingPath(method.getAnnotations())
                    .map(path -> normalizeEndpoint(basePath, path))
                    .orElse(null);
            if (endpoint != null) {
                counters[2]++;
            }
            String owner = ownerName(method);
            String parameters = method.getParameters().stream()
                    .map(parameter -> parameter.getTypeAsString() + " " + parameter.getNameAsString())
                    .collect(java.util.stream.Collectors.joining(", "));
            String annotations = method.getAnnotations().stream().map(AnnotationExpr::toString)
                    .collect(java.util.stream.Collectors.joining(" "));
            String calledSymbols = method.findAll(MethodCallExpr.class).stream()
                    .map(MethodCallExpr::getNameAsString).distinct().sorted()
                    .collect(java.util.stream.Collectors.joining(","));
            addChunk(chunks, taskId, relativePath, owner + "#" + method.getNameAsString(), endpoint,
                    start, end, truncate(sourceLines(content, start, end)),
                    "JAVA_METHOD", parameters, annotations, calledSymbols);
            counters[1]++;
        }
    }

    // 从 Spring Mapping 注解中提取类级或方法级路由片段。
    private java.util.Optional<String> mappingPath(com.github.javaparser.ast.NodeList<AnnotationExpr> annotations) {
        return annotations.stream()
                .filter(annotation -> annotation.getNameAsString().endsWith("Mapping"))
                .findFirst()
                .map(annotation -> {
                    String source = annotation.toString();
                    int firstQuote = source.indexOf('"');
                    int secondQuote = firstQuote < 0 ? -1 : source.indexOf('"', firstQuote + 1);
                    return firstQuote >= 0 && secondQuote > firstQuote
                            ? source.substring(firstQuote + 1, secondQuote) : "";
                });
    }

    private String ownerName(MethodDeclaration method) {
        Node current = method.getParentNode().orElse(null);
        while (current != null) {
            if (current instanceof ClassOrInterfaceDeclaration owner) {
                return owner.getNameAsString();
            }
            current = current.getParentNode().orElse(null);
        }
        return "UnknownClass";
    }

    // 将 XML、模板和解析失败源码切成有字符与行数上限的文本窗口。
    private void indexText(UUID taskId, String relativePath, String baseSymbol, String content,
                           List<CodeChunk> chunks, String chunkType) {
        String[] lines = content.split("\\R", -1);
        int lineIndex = 0;
        int part = 1;
        while (lineIndex < lines.length) {
            String line = lines[lineIndex];
            if (line.length() > MAX_TEXT_CHUNK_CHARS) {
                for (int offset = 0; offset < line.length(); offset += MAX_TEXT_CHUNK_CHARS) {
                    String segment = line.substring(offset, Math.min(offset + MAX_TEXT_CHUNK_CHARS, line.length()));
                    addChunk(chunks, taskId, relativePath, baseSymbol + "#part-" + part++, null,
                            lineIndex + 1, lineIndex + 1, segment, chunkType, "", "", "");
                }
                lineIndex++;
                continue;
            }
            int start = lineIndex;
            StringBuilder window = new StringBuilder();
            while (lineIndex < lines.length && lineIndex - start < MAX_TEXT_CHUNK_LINES) {
                String candidate = lines[lineIndex];
                if (candidate.length() > MAX_TEXT_CHUNK_CHARS) break;
                int separator = window.isEmpty() ? 0 : 1;
                if (!window.isEmpty() && window.length() + separator + candidate.length() > MAX_TEXT_CHUNK_CHARS) {
                    break;
                }
                if (!window.isEmpty()) window.append('\n');
                window.append(candidate);
                lineIndex++;
            }
            if (lineIndex == start) continue;
            addChunk(chunks, taskId, relativePath, baseSymbol + "#part-" + part++, null,
                    start + 1, Math.max(start + 1, lineIndex), window.toString(), chunkType, "", "", "");
        }
    }

    // 规范化 normalizeEndpoint 对应的输入。
    private String normalizeEndpoint(String base, String method) {
        String joined = ("/" + base + "/" + method).replaceAll("/+", "/");
        return joined.length() > 1 && joined.endsWith("/") ? joined.substring(0, joined.length() - 1) : joined;
    }

    // 向当前结果添加 addChunk 对应的数据。
    private void addChunk(List<CodeChunk> chunks, UUID taskId, String path, String symbol,
                          String endpoint, int start, int end, String content) {
        addChunk(chunks, taskId, path, symbol, endpoint, start, end, content, "TEXT", "", "", "");
    }

    // 向当前结果添加 addChunk 对应的数据。
    private void addChunk(List<CodeChunk> chunks, UUID taskId, String path, String symbol,
                          String endpoint, int start, int end, String content, String chunkType,
                          String parameters, String annotations, String calledSymbols) {
        chunks.add(new CodeChunk(taskId, path, symbol, endpoint, start, end, content,
                chunkType, parameters, annotations, calledSymbols));
    }

    private String extension(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "text" : path.substring(dot + 1);
    }

    // Recon 只读取构建描述和 Spring 应用配置原文；普通业务源码仍由本地画像和后续专业 Agent 处理。
    private List<Path> frameworkFilePaths(Path root) {
        List<Path> candidates;
        try (Stream<Path> paths = Files.walk(root)) {
            candidates = paths.filter(Files::isRegularFile)
                    .filter(path -> AuditSourceFilter.isFrameworkContext(
                            normalizePath(root.relativize(path).toString())))
                    .sorted(Comparator.comparingInt(this::frameworkPriority)
                            .thenComparing(path -> normalizePath(root.relativize(path).toString())))
                    .toList();
        } catch (IOException exception) {
            log.warn("无法完整收集 Recon 框架配置文件: {}", root, exception);
            return List.of();
        }
        return List.copyOf(candidates);
    }

    private List<ReconFrameworkFile> frameworkFiles(Path root, List<Path> candidates) {
        List<ReconFrameworkFile> result = new ArrayList<>();
        int remaining = MAX_FRAMEWORK_CONTEXT_CHARS;
        for (Path file : candidates) {
            if (remaining <= 0 || result.size() >= MAX_FRAMEWORK_FILES) break;
            try {
                String content = Files.readString(file, StandardCharsets.UTF_8);
                int length = Math.min(Math.min(content.length(), MAX_FRAMEWORK_FILE_CHARS), remaining);
                result.add(new ReconFrameworkFile(normalizePath(root.relativize(file).toString()),
                        frameworkFileKind(file), content.substring(0, length)));
                remaining -= length;
            } catch (Exception exception) {
                log.debug("跳过无法读取的 Recon 框架配置文件: {}", file, exception);
            }
        }
        return List.copyOf(result);
    }

    private Path safeResolve(Path root, String relativePath) {
        if (relativePath == null || relativePath.isBlank()) return null;
        Path normalizedRoot = root.toAbsolutePath().normalize();
        Path resolved = normalizedRoot.resolve(relativePath).normalize();
        return resolved.startsWith(normalizedRoot) ? resolved : null;
    }

    private boolean isFrameworkFile(Path file) {
        return AuditSourceFilter.isFrameworkContext(file.getFileName().toString());
    }

    private int frameworkPriority(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.equals("pom.xml") || name.startsWith("build.gradle") || name.startsWith("settings.gradle")) return 0;
        if (name.equals("application.yml") || name.equals("application.yaml")
                || name.equals("application.properties")) return 1;
        if (name.startsWith("application-")) return 2;
        if (name.startsWith("bootstrap")) return 3;
        return 4;
    }

    private String frameworkFileKind(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.equals("pom.xml") || name.startsWith("build.gradle") || name.startsWith("settings.gradle")) {
            return "BUILD_DESCRIPTOR";
        }
        return name.startsWith("bootstrap") ? "BOOTSTRAP_CONFIGURATION" : "APPLICATION_CONFIGURATION";
    }

    private String truncate(String value) {
        return value.length() <= 100_000 ? value : value.substring(0, 100_000);
    }

    private String sourceLines(String content, int startLine, int endLine) {
        String[] lines = content.split("\\R", -1);
        int from = Math.max(0, startLine - 1);
        int to = Math.min(lines.length, Math.max(from, endLine));
        return String.join("\n", java.util.Arrays.copyOfRange(lines, from, to));
    }

    private record LineRange(int start, int end) {
    }
}
