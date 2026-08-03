package com.deepaudit.recon;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.ChunkChangeType;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.mapper.CodeChunkMapper;
import com.deepaudit.source.AuditSourceFilter;
import com.deepaudit.semantic.IncrementalSemanticDiffService;
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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

// 负责 ReconService 对应的业务编排和处理。
@Slf4j
@Service
public class ReconService {

    private static final long MAX_SOURCE_FILE_BYTES = 2L * 1024L * 1024L;
    private static final int MAX_TEXT_CHUNK_CHARS = 12_000;
    private static final int MAX_TEXT_CHUNK_LINES = 160;
    private static final Set<String> TEXT_EXTENSIONS = Set.of(
            "java", "xml", "html", "htm", "jsp", "ftl", "vue", "jsx", "tsx", "js", "ts",
            "properties", "yml", "yaml", "sql"
    );

    private final CodeChunkMapper chunkMapper;
    private final IncrementalSemanticDiffService incrementalSemanticDiffService;
    private final ProjectTechnologyDetector technologyDetector = new ProjectTechnologyDetector();
    private final ProjectStructureProfiler structureProfiler = new ProjectStructureProfiler();

    // 创建 ReconService 实例并初始化所需依赖或状态。
    public ReconService(CodeChunkMapper chunkMapper) {
        this(chunkMapper, null);
    }

    // 创建 ReconService 实例并初始化所需依赖或状态。
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
        chunkMapper.deleteByTaskId(taskId);
        List<CodeChunk> chunks = new ArrayList<>();
        int[] counters = new int[3];
        try (Stream<Path> paths = Files.walk(root)) {
            // 只遍历受支持的文本源码，二进制和未知文件不进入模型上下文。
            paths.filter(Files::isRegularFile)
                    .filter(path -> AuditSourceFilter.shouldAnalyze(root, path))
                    .filter(this::isSupportedTextFile)
                    .forEach(path -> indexFile(taskId, root, path, chunks, counters));
        }
        applyIncrementalMetadata(chunks, changes);
        // 增量模式进一步比较 Base/Target 方法快照，覆盖纯删除、签名和安全 Guard 变化。
        if (incrementalSemanticDiffService != null) {
            incrementalSemanticDiffService.analyze(taskId, baseRoot, root, chunks, changes);
        }
        for (int start = 0; start < chunks.size(); start += 500) {
            chunkMapper.insertBatch(chunks.subList(start, Math.min(start + 500, chunks.size())));
        }
        // 独立识别构建工具、框架和安全组件，供 Recon Agent 理解项目背景。
        TechnologyProfile technologyProfile = technologyDetector.detect(root);
        // 所有代码块都参与结构化画像；仅输出模块、分层和事实计数，不携带具体位置或业务源码。
        ProjectStructureProfile projectStructure = structureProfiler.profile(root, chunks);
        return new ReconSummary(counters[0], counters[1], counters[2], chunks.size(),
                technologyProfile, projectStructure);
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

    // 增量影响范围在语义分析后才最终确定，因此在 Recon Agent 调用前刷新结构画像中的范围统计。
    public ReconSummary refreshProjectStructure(Path root, ReconSummary summary, List<CodeChunk> chunks) {
        return new ReconSummary(summary.sourceFileCount(), summary.javaMethodCount(), summary.endpointCount(),
                summary.chunkCount(), summary.technologyProfile(), structureProfiler.profile(root, chunks));
    }

    // 执行 ReconService 中的 applyIncrementalMetadata 处理。
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
            boolean direct = change.isConfigurationChange() || "ADD".equals(change.getChangeType())
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

    // 执行 ReconService 中的 overlaps 处理。
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

    // 执行 ReconService 中的 truncateBase 处理。
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
            counters[0]++;
            if (relativePath.endsWith(".java")) {
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

    // 执行 ReconService 中的 ownerName 处理。
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

    // 执行 ReconService 中的 extension 处理。
    private String extension(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "text" : path.substring(dot + 1);
    }

    // 判断是否满足 isSupportedTextFile 对应的条件。
    private boolean isSupportedTextFile(Path path) {
        String name = path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        return dot > 0 && TEXT_EXTENSIONS.contains(name.substring(dot + 1).toLowerCase(Locale.ROOT));
    }

    // 执行 ReconService 中的 truncate 处理。
    private String truncate(String value) {
        return value.length() <= 100_000 ? value : value.substring(0, 100_000);
    }

    // 执行 ReconService 中的 sourceLines 处理。
    private String sourceLines(String content, int startLine, int endLine) {
        String[] lines = content.split("\\R", -1);
        int from = Math.max(0, startLine - 1);
        int to = Math.min(lines.length, Math.max(from, endLine));
        return String.join("\n", java.util.Arrays.copyOfRange(lines, from, to));
    }
}
