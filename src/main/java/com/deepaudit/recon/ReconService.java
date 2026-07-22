package com.deepaudit.recon;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.rag.EmbeddingService;
import com.deepaudit.mapper.CodeChunkMapper;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParseProblemException;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

@Service
public class ReconService {

    private static final Logger log = LoggerFactory.getLogger(ReconService.class);
    private static final long MAX_SOURCE_FILE_BYTES = 2L * 1024L * 1024L;
    private static final int MAX_TEXT_CHUNK_CHARS = 12_000;
    private static final int MAX_TEXT_CHUNK_LINES = 160;
    private static final int MAX_EMBEDDING_INPUT_CHARS = 16_000;
    private static final Set<String> TEXT_EXTENSIONS = Set.of(
            "java", "xml", "html", "htm", "jsp", "ftl", "vue", "jsx", "tsx", "js", "ts",
            "properties", "yml", "yaml", "sql"
    );

    private final CodeChunkMapper chunkMapper;
    private final EmbeddingService embeddingService;
    private final ProjectTechnologyDetector technologyDetector = new ProjectTechnologyDetector();

    public ReconService(CodeChunkMapper chunkMapper, EmbeddingService embeddingService) {
        this.chunkMapper = chunkMapper;
        this.embeddingService = embeddingService;
        StaticJavaParser.setConfiguration(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));
    }

    // 扫描受支持源码，生成代码块、Embedding 和项目技术栈摘要。
    @Transactional
    public ReconSummary buildIndex(UUID taskId, Path root) throws IOException {
        // 重建前清空旧代码块，确保同一任务的索引可重复生成。
        chunkMapper.deleteByTaskId(taskId);
        List<CodeChunk> chunks = new ArrayList<>();
        int[] counters = new int[3];
        try (Stream<Path> paths = Files.walk(root)) {
            // 只遍历受支持的文本源码，二进制和未知文件不进入模型上下文。
            paths.filter(Files::isRegularFile)
                    .filter(this::isSupportedTextFile)
                    .forEach(path -> indexFile(taskId, root, path, chunks, counters));
        }
        // 批量生成向量并按代码块顺序回填，维持检索数据一一对应。
        List<String> embeddingInputs = chunks.stream().map(this::embeddingInput).toList();
        List<double[]> vectors = embeddingService.embedAll(embeddingInputs);
        if (vectors.size() != chunks.size()) {
            throw new IllegalStateException("Embedding 数量与代码块数量不一致");
        }
        for (int index = 0; index < chunks.size(); index++) {
            chunks.get(index).setEmbedding(embeddingService.serialize(vectors.get(index)));
        }
        for (int start = 0; start < chunks.size(); start += 500) {
            chunkMapper.insertBatch(chunks.subList(start, Math.min(start + 500, chunks.size())));
        }
        // 独立识别构建工具、框架和安全组件，供 Recon Agent 理解项目背景。
        TechnologyProfile technologyProfile = technologyDetector.detect(root);
        return new ReconSummary(counters[0], counters[1], counters[2], chunks.size(), technologyProfile);
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
                    start, end, truncate(method.toString()), "JAVA_METHOD", parameters, annotations, calledSymbols);
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

    private String normalizeEndpoint(String base, String method) {
        String joined = ("/" + base + "/" + method).replaceAll("/+", "/");
        return joined.length() > 1 && joined.endsWith("/") ? joined.substring(0, joined.length() - 1) : joined;
    }

    private void addChunk(List<CodeChunk> chunks, UUID taskId, String path, String symbol,
                          String endpoint, int start, int end, String content) {
        addChunk(chunks, taskId, path, symbol, endpoint, start, end, content, "TEXT", "", "", "");
    }

    private void addChunk(List<CodeChunk> chunks, UUID taskId, String path, String symbol,
                          String endpoint, int start, int end, String content, String chunkType,
                          String parameters, String annotations, String calledSymbols) {
        chunks.add(new CodeChunk(taskId, path, symbol, endpoint, start, end, content, "",
                chunkType, parameters, annotations, calledSymbols));
    }

    // 组合结构化元数据和源码正文作为 Embedding 输入，并限制模型载荷大小。
    private String embeddingInput(CodeChunk chunk) {
        String input = chunk.getFilePath() + " " + chunk.getSymbolName() + " "
                + (chunk.getEndpoint() == null ? "" : chunk.getEndpoint()) + " "
                + chunk.getParameters() + " " + chunk.getAnnotations() + " "
                + chunk.getCalledSymbols() + " " + chunk.getContent();
        return input.substring(0, Math.min(input.length(), MAX_EMBEDDING_INPUT_CHARS));
    }

    private String extension(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "text" : path.substring(dot + 1);
    }

    private boolean isSupportedTextFile(Path path) {
        String name = path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        return dot > 0 && TEXT_EXTENSIONS.contains(name.substring(dot + 1).toLowerCase(Locale.ROOT));
    }

    private String truncate(String value) {
        return value.length() <= 100_000 ? value : value.substring(0, 100_000);
    }
}
