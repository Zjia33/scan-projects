package com.deepaudit.recon;

import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.source.AuditSourceFilter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * 将完整项目索引压缩为 Recon 可消费的整体结构画像。所有代码块都参与统计，模型只接收聚合计数。
 */
@Slf4j
final class ProjectStructureProfiler {
    private static final long MAX_INSPECTED_FILE_BYTES = 2L * 1024L * 1024L;
    private static final Set<String> PROFILED_EXTENSIONS = Set.of(
            "java", "xml", "yml", "yaml", "properties", "gradle", "kts", "json");

    // 执行 ProjectStructureProfiler 中的 profile 处理。
    ProjectStructureProfile profile(Path root, List<CodeChunk> chunks) {
        List<Path> files = inspectableFiles(root);
        List<String> moduleRoots = discoverModuleRoots(root, files);
        Map<String, ModuleAccumulator> modules = new TreeMap<>();
        moduleRoots.forEach(module -> modules.put(module, new ModuleAccumulator(module)));
        Map<String, LayerAccumulator> layers = new TreeMap<>();
        FactIndex entryPoints = new FactIndex();
        FactIndex security = new FactIndex();
        FactIndex dataAccess = new FactIndex();
        FactIndex integrations = new FactIndex();
        FactIndex configurations = new FactIndex();

        for (CodeChunk chunk : chunks) {
            String path = normalize(chunk.getFilePath());
            String module = moduleFor(path, moduleRoots);
            ModuleAccumulator moduleStats = modules.computeIfAbsent(module, ModuleAccumulator::new);
            moduleStats.files.add(path);
            if ("JAVA_METHOD".equals(chunk.getChunkType())) moduleStats.javaMethodCount++;
            if (notBlank(chunk.getEndpoint())) moduleStats.endpointCount++;
            if (chunk.getAnalysisScope() == AnalysisScope.CHANGED) moduleStats.changedChunkCount++;
            if (chunk.getAnalysisScope() == AnalysisScope.IMPACTED) moduleStats.impactedChunkCount++;

            String layer = layer(chunk);
            LayerAccumulator layerStats = layers.computeIfAbsent(module + "\u0000" + layer,
                    ignored -> new LayerAccumulator(module, layer));
            layerStats.files.add(path);
            layerStats.codeChunkCount++;

            String searchable = searchable(chunk);
            inspectEntryPoints(entryPoints, module, chunk, searchable);
            inspectDataAccess(dataAccess, module, path, searchable);
            inspectIntegrations(integrations, module, searchable);
        }

        for (Path file : files) {
            String relative = normalize(root.relativize(file).toString());
            String module = moduleFor(relative, moduleRoots);
            if (isConfigurationFile(file)) {
                configurations.add(module, configurationKind(file));
            }
            inspectFileFacts(file, module, entryPoints, security, integrations);
        }

        return new ProjectStructureProfile(
                modules.values().stream().map(ModuleAccumulator::freeze).toList(),
                layers.values().stream().map(LayerAccumulator::freeze).toList(),
                entryPoints.freeze(), security.freeze(), dataAccess.freeze(), integrations.freeze(),
                configurations.freeze());
    }

    // 分析并提取 inspectableFiles 对应的事实。
    private List<Path> inspectableFiles(Path root) {
        try (Stream<Path> paths = Files.walk(root)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> AuditSourceFilter.shouldAnalyze(root, path))
                    .filter(this::isInspectable)
                    .sorted(Comparator.comparing(path -> normalize(root.relativize(path).toString())))
                    .toList();
        } catch (IOException exception) {
            log.warn("项目结构画像未完整读取文件树: {}", root, exception);
            return List.of();
        }
    }

    // 判断是否满足 isInspectable 对应的条件。
    private boolean isInspectable(Path file) {
        try {
            if (Files.size(file) > MAX_INSPECTED_FILE_BYTES) return false;
        } catch (IOException exception) {
            return false;
        }
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (isBuildDescriptor(name)) return true;
        int dot = name.lastIndexOf('.');
        return dot > 0 && PROFILED_EXTENSIONS.contains(name.substring(dot + 1));
    }

    // 执行 ProjectStructureProfiler 中的 discoverModuleRoots 处理。
    private List<String> discoverModuleRoots(Path root, List<Path> files) {
        Set<String> modules = new LinkedHashSet<>();
        for (Path file : files) {
            if (!isBuildDescriptor(file.getFileName().toString().toLowerCase(Locale.ROOT))) continue;
            Path parent = file.getParent();
            String relative = parent == null ? "." : normalize(root.relativize(parent).toString());
            modules.add(relative.isBlank() ? "." : relative);
        }
        if (modules.isEmpty()) modules.add(".");
        return modules.stream().sorted(Comparator.comparingInt(String::length).reversed()
                .thenComparing(Comparator.naturalOrder())).toList();
    }

    // 执行 ProjectStructureProfiler 中的 moduleFor 处理。
    private String moduleFor(String path, List<String> moduleRoots) {
        for (String module : moduleRoots) {
            if (".".equals(module) || path.equals(module) || path.startsWith(module + "/")) return module;
        }
        return ".";
    }

    // 分析并提取 inspectEntryPoints 对应的事实。
    private void inspectEntryPoints(FactIndex facts, String module, CodeChunk chunk,
                                    String searchable) {
        if (notBlank(chunk.getEndpoint())) {
            facts.add(module, httpKind(chunk.getAnnotations()));
        }
        addIfContains(facts, module, "KAFKA_LISTENER", searchable, "kafkalistener");
        addIfContains(facts, module, "RABBIT_LISTENER", searchable, "rabbitlistener");
        addIfContains(facts, module, "JMS_LISTENER", searchable, "jmslistener");
        addIfContains(facts, module, "SCHEDULED_JOB", searchable, "scheduled");
        addIfContains(facts, module, "WEBSOCKET_MESSAGE", searchable, "messagemapping");
    }

    // 分析并提取 inspectDataAccess 对应的事实。
    private void inspectDataAccess(FactIndex facts, String module, String path, String searchable) {
        addIfContainsAny(facts, module, "JDBC", searchable,
                "jdbctemplate", "namedparameterjdbctemplate", "preparestatement", "createstatement");
        addIfContainsAny(facts, module, "MYBATIS", searchable,
                "sqlsession", "selectone", "selectlist", "@select", "@insert", "@update", "@delete");
        addIfContainsAny(facts, module, "JPA_HIBERNATE", searchable,
                "entitymanager", "createquery", "createnativequery", "@query");
        addIfContainsAny(facts, module, "REPOSITORY", searchable,
                "repository.", ".save(", ".findby", ".deleteby");
        if (path.endsWith("mapper.xml")) facts.add(module, "MYBATIS_XML");
        addIfContainsAny(facts, module, "REDIS", searchable,
                "redistemplate", "stringredistemplate", "redisrepository");
    }

    // 分析并提取 inspectIntegrations 对应的事实。
    private void inspectIntegrations(FactIndex facts, String module, String searchable) {
        addIfContainsAny(facts, module, "KAFKA", searchable, "kafkatemplate", "kafkalistener");
        addIfContainsAny(facts, module, "RABBITMQ", searchable, "rabbittemplate", "rabbitlistener");
        addIfContainsAny(facts, module, "JMS", searchable, "jmstemplate", "jmslistener");
        addIfContainsAny(facts, module, "OUTBOUND_HTTP", searchable,
                "resttemplate", "webclient", "httpclient", "okhttp", "retrofit");
        addIfContainsAny(facts, module, "OBJECT_STORAGE", searchable,
                "s3client", "minio", "blobclient", "ossclient");
        addIfContainsAny(facts, module, "EMAIL", searchable,
                "javamailsender", "mailsender", "sendemail");
    }

    // 分析并提取 inspectFileFacts 对应的事实。
    private void inspectFileFacts(Path file, String module, FactIndex entryPoints,
                                  FactIndex security, FactIndex integrations) {
        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        } catch (Exception exception) {
            log.debug("跳过无法生成项目结构事实的文件: {}", file, exception);
            return;
        }
        addIfContainsAny(entryPoints, module, "SERVLET_FILTER", content,
                "extends onceperrequestfilter", "implements filter", "filterregistrationbean");
        addIfContains(integrations, module, "FEIGN_CLIENT", content, "@feignclient");

        addIfContainsAny(security, module, "SECURITY_FILTER_CHAIN", content,
                "securityfilterchain", "websecurityconfigureradapter");
        addIfContainsAny(security, module, "ROUTE_AUTHORIZATION", content,
                "authorizehttprequests", "authorizerequests", "requestmatchers", "antmatchers");
        addIfContains(security, module, "PUBLIC_ROUTE", content, "permitall");
        addIfContainsAny(security, module, "METHOD_SECURITY", content,
                "enablemethodsecurity", "enableglobalmethodsecurity", "preauthorize", "postauthorize",
                "@secured", "rolesallowed", "requirespermissions", "sacheckpermission");
        addIfContainsAny(security, module, "CSRF_CONFIGURATION", content,
                ".csrf(", "csrf::", "csrfdisable", "csrf.enabled");
        addIfContainsAny(security, module, "CORS_CONFIGURATION", content,
                ".cors(", "corsconfiguration", "allowedorigins", "allowedoriginpatterns");
        addIfContainsAny(security, module, "SESSION_MANAGEMENT", content,
                "sessionmanagement", "sessioncreationpolicy", "maximumsessions");
        addIfContainsAny(security, module, "JWT", content,
                "jwtdecoder", "jwtencoder", "jsonwebtoken", "jjwt", "oauth2resourceserver");
        addIfContainsAny(security, module, "OAUTH2_OIDC", content,
                "oauth2login", "oauth2client", "openid", "oidc", "keycloak");
        addIfContainsAny(security, module, "CUSTOM_SECURITY_FILTER", content,
                "addfilterbefore", "addfilterafter", "addfilterat");
    }

    // 执行 ProjectStructureProfiler 中的 layer 处理。
    private String layer(CodeChunk chunk) {
        String value = (normalize(chunk.getFilePath()) + " " + safe(chunk.getSymbolName())).toLowerCase(Locale.ROOT);
        if (notBlank(chunk.getEndpoint()) || containsAny(value, "controller", "/web/", "/api/")) return "WEB";
        if (containsAny(value, "security", "config", "filter", "interceptor")) return "SECURITY_CONFIGURATION";
        if (containsAny(value, "repository", "mapper", "dao", "/persistence/")) return "DATA_ACCESS";
        if (containsAny(value, "service", "usecase", "applicationservice")) return "SERVICE";
        if (containsAny(value, "client", "gateway", "adapter")) return "INTEGRATION";
        if (containsAny(value, "listener", "consumer", "subscriber")) return "MESSAGING";
        if (containsAny(value, "schedule", "scheduler", "job")) return "SCHEDULER";
        if (containsAny(value, "entity", "domain", "aggregate")) return "DOMAIN";
        if (containsAny(value, "dto", "request", "response", "vo")) return "DATA_MODEL";
        if (!"JAVA_METHOD".equals(chunk.getChunkType())) return "RESOURCE";
        return "OTHER";
    }

    // 执行 ProjectStructureProfiler 中的 httpKind 处理。
    private String httpKind(String annotations) {
        String value = safe(annotations).toLowerCase(Locale.ROOT);
        if (value.contains("getmapping")) return "HTTP_GET";
        if (value.contains("postmapping")) return "HTTP_POST";
        if (value.contains("putmapping")) return "HTTP_PUT";
        if (value.contains("patchmapping")) return "HTTP_PATCH";
        if (value.contains("deletemapping")) return "HTTP_DELETE";
        return "HTTP_ENDPOINT";
    }

    // 查询并返回 searchable 对应的数据。
    private String searchable(CodeChunk chunk) {
        return (safe(chunk.getFilePath()) + " " + safe(chunk.getSymbolName()) + " "
                + safe(chunk.getAnnotations()) + " " + safe(chunk.getCalledSymbols()) + " "
                + safe(chunk.getContent())).toLowerCase(Locale.ROOT);
    }

    // 向当前结果添加 addIfContains 对应的数据。
    private void addIfContains(FactIndex facts, String module, String kind, String searchable, String marker) {
        if (searchable.contains(marker)) facts.add(module, kind);
    }

    // 向当前结果添加 addIfContainsAny 对应的数据。
    private void addIfContainsAny(FactIndex facts, String module, String kind, String searchable,
                                  String... markers) {
        if (containsAny(searchable, markers)) facts.add(module, kind);
    }

    // 判断是否满足 containsAny 对应的条件。
    private boolean containsAny(String value, String... markers) {
        for (String marker : markers) {
            if (value.contains(marker)) return true;
        }
        return false;
    }

    // 判断是否满足 isBuildDescriptor 对应的条件。
    private boolean isBuildDescriptor(String name) {
        return name.equals("pom.xml") || name.equals("package.json") || name.startsWith("build.gradle")
                || name.startsWith("settings.gradle");
    }

    // 判断是否满足 isConfigurationFile 对应的条件。
    private boolean isConfigurationFile(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (isBuildDescriptor(name) || name.startsWith("application.") || name.startsWith("bootstrap.")) return true;
        return name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".properties")
                || name.endsWith(".xml");
    }

    // 执行 ProjectStructureProfiler 中的 configurationKind 处理。
    private String configurationKind(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (isBuildDescriptor(name)) return "BUILD_DESCRIPTOR";
        if (name.startsWith("application.") || name.startsWith("bootstrap.")) return "APPLICATION_CONFIGURATION";
        if (name.endsWith("mapper.xml")) return "MYBATIS_MAPPING";
        if (name.endsWith(".xml")) return "XML_CONFIGURATION";
        return "RUNTIME_CONFIGURATION";
    }

    // 执行 ProjectStructureProfiler 中的 notBlank 处理。
    private boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    // 执行 ProjectStructureProfiler 中的 safe 处理。
    private String safe(String value) {
        return value == null ? "" : value;
    }

    // 规范化 normalize 对应的输入。
    private String normalize(String value) {
        if (value == null || value.isBlank()) return ".";
        return value.replace('\\', '/');
    }

    // 封装 ModuleAccumulator 相关的数据与处理逻辑。
    private static final class ModuleAccumulator {
        private final String path;
        private final Set<String> files = new LinkedHashSet<>();
        private int javaMethodCount;
        private int endpointCount;
        private int changedChunkCount;
        private int impactedChunkCount;

        // 创建 ModuleAccumulator 实例并初始化所需依赖或状态。
        private ModuleAccumulator(String path) {
            this.path = path;
        }

        // 执行 ModuleAccumulator 中的 freeze 处理。
        private ProjectStructureProfile.ModuleProfile freeze() {
            return new ProjectStructureProfile.ModuleProfile(path, files.size(), javaMethodCount,
                    endpointCount, changedChunkCount, impactedChunkCount);
        }
    }

    // 封装 LayerAccumulator 相关的数据与处理逻辑。
    private static final class LayerAccumulator {
        private final String module;
        private final String layer;
        private final Set<String> files = new LinkedHashSet<>();
        private int codeChunkCount;

        // 创建 LayerAccumulator 实例并初始化所需依赖或状态。
        private LayerAccumulator(String module, String layer) {
            this.module = module;
            this.layer = layer;
        }

        // 执行 LayerAccumulator 中的 freeze 处理。
        private ProjectStructureProfile.LayerProfile freeze() {
            return new ProjectStructureProfile.LayerProfile(module, layer, files.size(), codeChunkCount);
        }
    }

    // 封装 FactIndex 相关的数据与处理逻辑。
    private static final class FactIndex {
        private final Map<String, FactAccumulator> values = new TreeMap<>();

        // 向当前结果添加 add 对应的数据。
        private void add(String module, String kind) {
            values.computeIfAbsent(module + "\u0000" + kind, ignored -> new FactAccumulator(module, kind))
                    .increment();
        }

        // 执行 FactIndex 中的 freeze 处理。
        private List<ProjectStructureProfile.FactGroup> freeze() {
            return values.values().stream().map(FactAccumulator::freeze).toList();
        }
    }

    // 封装 FactAccumulator 相关的数据与处理逻辑。
    private static final class FactAccumulator {
        private final String module;
        private final String kind;
        private int occurrenceCount;

        // 创建 FactAccumulator 实例并初始化所需依赖或状态。
        private FactAccumulator(String module, String kind) {
            this.module = module;
            this.kind = kind;
        }

        // 向当前结果添加 add 对应的数据。
        private void increment() {
            occurrenceCount++;
        }

        // 执行 FactAccumulator 中的 freeze 处理。
        private ProjectStructureProfile.FactGroup freeze() {
            return new ProjectStructureProfile.FactGroup(module, kind, occurrenceCount);
        }
    }
}
