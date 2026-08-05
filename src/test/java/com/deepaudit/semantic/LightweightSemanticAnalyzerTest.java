package com.deepaudit.semantic;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class LightweightSemanticAnalyzerTest {

    @TempDir
    Path root;

    @Test
    void resolvesSpringInterfaceMyBatisXmlAndTaintedParameterAcrossFiles() throws Exception {
        write("src/main/java/demo/OrderController.java", """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                @RequestMapping("/orders")
                class OrderController {
                    private final OrderService service;
                    OrderController(OrderService service) { this.service = service; }
                    @GetMapping("/{id}")
                    Object detail(@PathVariable Long id) {
                        return service.getById(id);
                    }
                }
                """);
        write("src/main/java/demo/OrderService.java", """
                package demo;
                interface OrderService {
                    Object getById(Long id);
                }
                """);
        write("src/main/java/demo/OrderServiceImpl.java", """
                package demo;
                import org.springframework.stereotype.Service;
                @Service
                class OrderServiceImpl implements OrderService {
                    private final OrderMapper mapper;
                    OrderServiceImpl(OrderMapper mapper) { this.mapper = mapper; }
                    public Object getById(Long id) {
                        return mapper.selectById(id);
                    }
                }
                """);
        write("src/main/java/demo/OrderMapper.java", """
                package demo;
                interface OrderMapper {
                    Object selectById(Long id);
                }
                """);
        write("src/main/resources/mapper/OrderMapper.xml", """
                <mapper namespace="demo.OrderMapper">
                  <select id="selectById" resultType="map">
                    SELECT * FROM orders WHERE id = ${id}
                  </select>
                </mapper>
                """);

        UUID taskId = UUID.randomUUID();
        List<CodeChunk> chunks = new ArrayList<>();
        chunks.add(chunk(1L, taskId, "src/main/java/demo/OrderController.java", "OrderController#detail",
                "/orders/{id}", 8, 11, "Object detail(Long id) { return service.getById(id); }", "JAVA_METHOD", "Long id"));
        chunks.add(chunk(2L, taskId, "src/main/java/demo/OrderService.java", "OrderService#getById",
                null, 3, 3, "Object getById(Long id);", "JAVA_METHOD", "Long id"));
        chunks.add(chunk(3L, taskId, "src/main/java/demo/OrderServiceImpl.java", "OrderServiceImpl#getById",
                null, 7, 9, "public Object getById(Long id) { return mapper.selectById(id); }", "JAVA_METHOD", "Long id"));
        chunks.add(chunk(4L, taskId, "src/main/java/demo/OrderMapper.java", "OrderMapper#selectById",
                null, 3, 3, "Object selectById(Long id);", "JAVA_METHOD", "Long id"));
        chunks.add(chunk(5L, taskId, "src/main/resources/mapper/OrderMapper.xml", "OrderMapper.xml#part-1",
                null, 1, 5, Files.readString(root.resolve("src/main/resources/mapper/OrderMapper.xml")), "TEXT_XML", ""));

        SemanticAnalysisProperties properties = new SemanticAnalysisProperties();
        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(properties)
                .enrich(taskId, root, chunks, Set.of(1L, 2L, 3L, 4L, 5L));

        assertThat(result.edges()).extracting(edge -> edge.getEdgeType())
                .contains("MYBATIS_XML").doesNotContain("CODEGRAPH_CALL");
        assertThat(result.edges()).anySatisfy(edge -> {
            if ("MYBATIS_XML".equals(edge.getEdgeType())) {
                assertThat(edge.getConfidence().name()).isEqualTo("HIGH");
                assertThat(edge.getCalleeChunkId()).isEqualTo(5L);
            }
        });
        assertThat(result.flows()).noneMatch(flow -> flow.getPathText().contains("OrderServiceImpl"));
    }

    @Test
    void ownershipGuardSuppressesHorizontalAuthorizationFlow() throws Exception {
        write("src/main/java/demo/SafeController.java", """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                class SafeController {
                    @GetMapping("/orders/{id}")
                    Object detail(@PathVariable Long id) {
                        Long currentUserId = SecurityContext.currentUserId();
                        return repository.findByIdAndOwnerId(id, currentUserId);
                    }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk chunk = chunk(10L, taskId, "src/main/java/demo/SafeController.java", "SafeController#detail",
                "/orders/{id}", 6, 10, Files.readString(root.resolve("src/main/java/demo/SafeController.java")),
                "JAVA_METHOD", "Long id");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(chunk), Set.of(10L));

        assertThat(result.flows()).noneMatch(flow -> flow.getType() == VulnerabilityType.AUTHORIZATION);
    }

    @Test
    void keepsOwnershipAndRoleEvidenceAsTwoDimensionsOfAuthorization() throws Exception {
        write("src/main/java/demo/AdminController.java", """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                class AdminController {
                    @DeleteMapping("/admin/orders/{id}")
                    void delete(@PathVariable Long id) {
                        repository.deleteById(id);
                    }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk endpoint = chunk(15L, taskId, "src/main/java/demo/AdminController.java", "AdminController#delete",
                "/admin/orders/{id}", 5, 8, Files.readString(root.resolve("src/main/java/demo/AdminController.java")),
                "JAVA_METHOD", "Long id");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(endpoint), Set.of(15L));

        List<SecurityFlow> authorizationFlows = result.flows().stream()
                .filter(flow -> flow.getType() == VulnerabilityType.AUTHORIZATION)
                .toList();
        assertThat(authorizationFlows).hasSize(2);
        assertThat(authorizationFlows).extracting(SecurityFlow::getSourceDescription)
                .containsExactlyInAnyOrder("接口资源标识参数", "HTTP 敏感业务入口");
    }

    @Test
    void springSecurityRolePolicySuppressesRoleAuthorizationDimension() throws Exception {
        write("src/main/java/demo/AdminController.java", """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                class AdminController {
                    @DeleteMapping("/admin/orders/{id}")
                    void delete(@PathVariable Long id) {
                        repository.deleteById(id);
                    }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk endpoint = chunk(20L, taskId, "src/main/java/demo/AdminController.java", "AdminController#delete",
                "/admin/orders/{id}", 5, 8, Files.readString(root.resolve("src/main/java/demo/AdminController.java")),
                "JAVA_METHOD", "Long id");
        CodeChunk security = chunk(21L, taskId, "src/main/java/demo/SecurityConfig.java", "SecurityConfig#filterChain",
                null, 1, 3, "http.authorizeHttpRequests(auth -> auth.requestMatchers(\"/admin/**\").hasRole(\"ADMIN\"));",
                "JAVA_METHOD", "");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(endpoint, security), Set.of(20L, 21L));

        assertThat(result.flows()).noneMatch(flow -> flow.getType() == VulnerabilityType.AUTHORIZATION
                && "HTTP 敏感业务入口".equals(flow.getSourceDescription()));
    }

    @Test
    void createsFrameworkBoundaryForInheritedRepositoryMethod() throws Exception {
        write("src/main/java/demo/InventoryController.java", """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                class InventoryController {
                    private OrderRepository repository;
                    @GetMapping("/orders/{id}")
                    Object detail(@PathVariable Long id) {
                        return repository.findById(id);
                    }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk endpoint = chunk(30L, taskId, "src/main/java/demo/InventoryController.java",
                "InventoryController#detail", "/orders/{id}", 1, 20,
                Files.readString(root.resolve("src/main/java/demo/InventoryController.java")),
                "JAVA_METHOD", "Long id");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(endpoint), Set.of(30L));

        assertThat(result.edges()).anySatisfy(edge -> {
            if ("PERSISTENCE_API".equals(edge.getEdgeType())) {
                assertThat(edge.getConfidence().name()).isEqualTo("HIGH");
                assertThat(edge.getResolutionReason()).contains("持久层边界");
            }
        });
        assertThat(result.coverage().frameworkEdges()).isEqualTo(1);
        assertThat(result.flows()).anyMatch(flow -> flow.getType() == VulnerabilityType.AUTHORIZATION
                && flow.getPathText().contains("PERSISTENCE_API"));
    }

    @Test
    void doesNotBuildASecondProjectCallGraphFromLocalMethodNames() throws Exception {
        write("src/main/java/demo/LegacyController.java", """
                package demo;
                class LegacyController {
                    private Object legacy;
                    Object detail(Long id) {
                        return legacy.load(id);
                    }
                }
                """);
        write("src/main/java/demo/LegacyLookup.java", """
                package demo;
                class LegacyLookup {
                    Object load(Long id) { return id; }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk caller = chunk(40L, taskId, "src/main/java/demo/LegacyController.java",
                "LegacyController#detail", null, 1, 20,
                Files.readString(root.resolve("src/main/java/demo/LegacyController.java")),
                "JAVA_METHOD", "Long id");
        CodeChunk callee = chunk(41L, taskId, "src/main/java/demo/LegacyLookup.java",
                "LegacyLookup#load", null, 1, 20,
                Files.readString(root.resolve("src/main/java/demo/LegacyLookup.java")),
                "JAVA_METHOD", "Long id");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(caller, callee), Set.of(40L, 41L));

        assertThat(result.edges()).noneMatch(edge -> "CODEGRAPH_CALL".equals(edge.getEdgeType()));
    }

    @Test
    void propagatesDtoSetterTaintAcrossServiceAndPersistentTemplate() throws Exception {
        write("src/main/java/demo/CommentController.java", """
                package demo;
                import org.springframework.web.bind.annotation.*;
                @RestController
                class CommentController {
                    private CommentService service;
                    @PostMapping("/comments")
                    void create(String content) {
                        CommentCommand command = new CommentCommand();
                        command.setContent(content);
                        service.save(command);
                    }
                }
                """);
        write("src/main/java/demo/CommentService.java", """
                package demo;
                class CommentService {
                    private CommentRepository repository;
                    void save(CommentCommand command) {
                        repository.save(command.getContent());
                    }
                }
                """);
        write("src/main/java/demo/CommentCommand.java", """
                package demo;
                class CommentCommand {
                    private String content;
                    void setContent(String content) { this.content = content; }
                    String getContent() { return content; }
                }
                """);
        write("src/main/resources/templates/comment.html", "<div v-html=\"comment.content\"></div>");
        UUID taskId = UUID.randomUUID();
        List<CodeChunk> chunks = List.of(
                chunk(50L, taskId, "src/main/java/demo/CommentController.java", "CommentController#create",
                        "/comments", 1, 30, Files.readString(root.resolve("src/main/java/demo/CommentController.java")),
                        "JAVA_METHOD", "String content"),
                chunk(51L, taskId, "src/main/java/demo/CommentService.java", "CommentService#save",
                        null, 1, 30, Files.readString(root.resolve("src/main/java/demo/CommentService.java")),
                        "JAVA_METHOD", "CommentCommand command"),
                chunk(52L, taskId, "src/main/java/demo/CommentCommand.java", "CommentCommand#methods",
                        null, 1, 30, Files.readString(root.resolve("src/main/java/demo/CommentCommand.java")),
                        "JAVA_METHOD", ""),
                chunk(53L, taskId, "src/main/resources/templates/comment.html", "comment.html#part-1",
                        null, 1, 1, Files.readString(root.resolve("src/main/resources/templates/comment.html")),
                        "TEXT_HTML", ""));

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, chunks, Set.of(50L, 51L, 52L, 53L));

        assertThat(result.flows()).noneMatch(item -> item.getType() == VulnerabilityType.STORED_XSS
                && item.getPathText().contains("CommentController")
                && item.getPathText().contains("CommentService"));
    }

    @Test
    void connectsSpringPublisherToTypedEventListener() throws Exception {
        write("src/main/java/demo/EventPublisher.java", """
                package demo;
                class EventPublisher {
                    private ApplicationEventPublisher publisher;
                    void submit(String content) {
                        publisher.publishEvent(new CommentCreated(content));
                    }
                }
                record CommentCreated(String content) {}
                """);
        write("src/main/java/demo/EventConsumer.java", """
                package demo;
                class EventConsumer {
                    @EventListener
                    void on(CommentCreated event) {
                        repository.save(event.content());
                    }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk publisher = chunk(60L, taskId, "src/main/java/demo/EventPublisher.java", "EventPublisher#submit",
                null, 1, 30, Files.readString(root.resolve("src/main/java/demo/EventPublisher.java")),
                "JAVA_METHOD", "String content");
        CodeChunk consumer = chunk(61L, taskId, "src/main/java/demo/EventConsumer.java", "EventConsumer#on",
                null, 1, 30, Files.readString(root.resolve("src/main/java/demo/EventConsumer.java")),
                "JAVA_METHOD", "CommentCreated event");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(publisher, consumer), Set.of(60L, 61L));

        assertThat(result.edges()).anySatisfy(edge -> {
            if ("SPRING_EVENT".equals(edge.getEdgeType())) {
                assertThat(edge.getCallerChunkId()).isEqualTo(60L);
                assertThat(edge.getCalleeChunkId()).isEqualTo(61L);
                assertThat(edge.getArgumentMapping()).contains("0<-0");
            }
        });
        assertThat(result.edges()).filteredOn(edge -> "publishEvent".equals(edge.getCalledName()))
                .allMatch(edge -> edge.getCalleeChunkId() != null);
    }

    @Test
    void excludesTestSourcesFromSemanticSymbolsAndCallGraph() throws Exception {
        write("src/main/java/demo/OrderService.java", """
                package demo;
                class OrderService {
                    void submit() { repository.save(); }
                }
                """);
        write("src/test/java/demo/OrderServiceTest.java", """
                package demo;
                class OrderServiceTest {
                    void submitUnsafeInput() { statement.execute(userInput); }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk production = chunk(70L, taskId, "src/main/java/demo/OrderService.java",
                "OrderService#submit", null, 3, 3,
                "void submit() { repository.save(); }", "JAVA_METHOD", "");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(production), Set.of(70L));

        assertThat(result.symbols()).extracting(symbol -> symbol.getFilePath())
                .contains("src/main/java/demo/OrderService.java")
                .noneMatch(path -> path.contains("/test/"));
        assertThat(result.symbols()).extracting(symbol -> symbol.getSimpleName())
                .doesNotContain("submitUnsafeInput");
    }

    @Test
    void parsesOnlyScopedMethodsWithoutInventingCrossMethodRelations() throws Exception {
        write("src/main/java/demo/EntryController.java", """
                package demo;
                class EntryController {
                    Object entry(String input) { return service.run(input); }
                }
                """);
        write("src/main/java/demo/DangerService.java", """
                package demo;
                class DangerService {
                    Object load(String input) { return statement.execute(input); }
                }
                """);
        write("src/main/java/demo/UnrelatedService.java", """
                package demo;
                class UnrelatedService {
                    void ignored() { statement.execute(userInput); }
                }
                """);
        UUID taskId = UUID.randomUUID();
        CodeChunk entry = chunk(80L, taskId, "src/main/java/demo/EntryController.java",
                "EntryController#entry", "/entry", 1, 10,
                Files.readString(root.resolve("src/main/java/demo/EntryController.java")),
                "JAVA_METHOD", "String input");
        CodeChunk danger = chunk(81L, taskId, "src/main/java/demo/DangerService.java",
                "DangerService#load", null, 1, 10,
                Files.readString(root.resolve("src/main/java/demo/DangerService.java")),
                "JAVA_METHOD", "String input");
        CodeChunk unrelated = chunk(82L, taskId, "src/main/java/demo/UnrelatedService.java",
                "UnrelatedService#ignored", null, 1, 10,
                Files.readString(root.resolve("src/main/java/demo/UnrelatedService.java")),
                "JAVA_METHOD", "");

        LightweightSemanticAnalyzer.Result result = new LightweightSemanticAnalyzer(new SemanticAnalysisProperties())
                .enrich(taskId, root, List.of(entry, danger, unrelated), Set.of(80L, 81L));

        assertThat(result.symbols()).extracting(symbol -> symbol.getChunkId()).doesNotContain(82L);
        assertThat(result.edges()).noneMatch(edge -> "CODEGRAPH_CALL".equals(edge.getEdgeType()));
    }

    private CodeChunk chunk(Long id, UUID taskId, String file, String symbol, String endpoint,
                            int start, int end, String content, String type, String parameters) {
        CodeChunk chunk = new CodeChunk(taskId, file, symbol, endpoint, start, end, content,
                type, parameters, "", "");
        chunk.setId(id);
        return chunk;
    }

    private void write(String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
