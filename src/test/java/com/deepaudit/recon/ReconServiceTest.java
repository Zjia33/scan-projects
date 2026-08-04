package com.deepaudit.recon;

import com.deepaudit.codegraph.CodeGraphClient;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.AnalysisScope;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.mapper.CodeChunkMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ReconServiceTest {

    @TempDir
    Path projectRoot;

    @Test
    void incrementalIndexOnlyPersistsChunksOverlappingChangedLines() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        UUID taskId = UUID.randomUUID();
        Path changed = projectRoot.resolve("src/main/java/demo/Changed.java");
        Path unchanged = projectRoot.resolve("src/main/java/demo/Unchanged.java");
        Files.createDirectories(changed.getParent());
        Files.writeString(changed, "class Changed {\n  void changed() { run(); }\n  void context() { stay(); }\n}");
        Files.writeString(unchanged, "class Unchanged { void untouched() {} }");
        GitFileChange change = new GitFileChange(taskId, "src/main/java/demo/Changed.java",
                "src/main/java/demo/Changed.java", "MODIFY", 1, 1, "2:2", "2:2", "diff", false);

        new ReconService(mapper).buildIndex(taskId, projectRoot, projectRoot, List.of(change));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CodeChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        assertThat(captor.getValue()).singleElement().satisfies(chunk -> {
            assertThat(chunk.getFilePath()).isEqualTo("src/main/java/demo/Changed.java");
            assertThat(chunk.getSymbolName()).endsWith("#changed");
            assertThat(chunk.getAnalysisScope()).isEqualTo(AnalysisScope.CHANGED);
        });
    }

    @Test
    void materializesOnlyMethodsReportedByCodeGraph() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        when(mapper.findByTaskId(org.mockito.ArgumentMatchers.any())).thenReturn(List.of());
        UUID taskId = UUID.randomUUID();
        Path source = projectRoot.resolve("src/main/java/demo/Service.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "class Service {\n  void impacted() { sink(); }\n  void unrelated() { noop(); }\n}");
        CodeGraphClient.CodeGraphLocation location = new CodeGraphClient.CodeGraphLocation(
                "demo.Service.impacted", "method", "src/main/java/demo/Service.java", 2);

        int materialized = new ReconService(mapper).materializeCodeGraphLocations(
                taskId, projectRoot, List.of(location));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CodeChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        assertThat(materialized).isEqualTo(1);
        assertThat(captor.getValue()).singleElement()
                .satisfies(chunk -> assertThat(chunk.getSymbolName()).endsWith("#impacted"));
    }

    @Test
    void preservesChangedJavaLinesOutsideMethodsAsDirectEvidence() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        UUID taskId = UUID.randomUUID();
        Path source = projectRoot.resolve("src/main/java/demo/SecurityConfig.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "class SecurityConfig {\n  String password = \"changed\";\n  void configure() {}\n}");
        GitFileChange change = new GitFileChange(taskId, "src/main/java/demo/SecurityConfig.java",
                "src/main/java/demo/SecurityConfig.java", "MODIFY", 1, 1,
                "2:2", "2:2", "field diff", false);

        new ReconService(mapper).buildIndex(taskId, projectRoot, projectRoot, List.of(change));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CodeChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        assertThat(captor.getValue()).singleElement().satisfies(chunk -> {
            assertThat(chunk.getChunkType()).isEqualTo("JAVA_CHANGE");
            assertThat(chunk.getContent()).contains("password");
            assertThat(chunk.getAnalysisScope()).isEqualTo(AnalysisScope.CHANGED);
        });
    }

    @Test
    void indexesLargeTemplateAsBoundedLineAwareChunks() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);

        List<String> lines = new ArrayList<>();
        for (int line = 1; line <= 220; line++) {
            lines.add(line == 190 ? "<div v-html=\"comment.content\"></div>" : "<p>line-" + line + "</p>");
        }
        Path template = projectRoot.resolve("src/main/resources/templates/comment.html");
        Files.createDirectories(template.getParent());
        Files.writeString(template, String.join("\n", lines));

        ReconSummary summary = buildIncremental(new ReconService(mapper));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CodeChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        List<CodeChunk> indexed = captor.getValue();
        assertThat(summary.sourceFileCount()).isEqualTo(1);
        assertThat(indexed).hasSizeGreaterThan(1);
        assertThat(indexed).allMatch(chunk -> chunk.getContent().length() <= 12_000);
        assertThat(indexed).anySatisfy(chunk -> {
            assertThat(chunk.getContent()).contains("v-html");
            assertThat(chunk.getStartLine()).isLessThanOrEqualTo(190);
            assertThat(chunk.getEndLine()).isGreaterThanOrEqualTo(190);
        });
    }

    @Test
    void detectsSecurityFrameworksAndAnnotationsAsReconFacts() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);

        Files.writeString(projectRoot.resolve("pom.xml"), """
                <project><dependencies><dependency>
                  <artifactId>spring-boot-starter-security</artifactId>
                </dependency></dependencies></project>
                """);
        Path controller = projectRoot.resolve("src/main/java/demo/AdminController.java");
        Files.createDirectories(controller.getParent());
        Files.writeString(controller, """
                package demo;
                import org.springframework.security.access.prepost.PreAuthorize;
                import org.springframework.web.bind.annotation.RestController;
                @RestController class AdminController {
                    @PreAuthorize("hasRole('ADMIN')") void deleteUser() {}
                }
                """);

        ReconSummary summary = buildIncremental(new ReconService(mapper));

        assertThat(summary.technologyProfile().buildTools()).contains("Maven");
        assertThat(summary.technologyProfile().frameworks()).contains("Spring MVC");
        assertThat(summary.technologyProfile().securityFrameworks()).contains("Spring Security");
        assertThat(summary.technologyProfile().securityAnnotations()).contains("@PreAuthorize");
        assertThat(summary.technologyProfile().evidence()).anyMatch(item -> item.contains("pom.xml"));
    }

    @Test
    void buildsCompleteStructuredProjectProfileWithoutBusinessSourceBodies() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);

        write("pom.xml", """
                <project><dependencies>
                  <dependency><artifactId>spring-boot-starter-security</artifactId></dependency>
                  <dependency><artifactId>spring-kafka</artifactId></dependency>
                </dependencies></project>
                """);
        write("src/main/resources/application.yml", "spring:\n  application:\n    name: orders");
        write("src/main/java/demo/OrderController.java", """
                package demo;
                @org.springframework.web.bind.annotation.RequestMapping("/orders")
                class OrderController {
                    @org.springframework.web.bind.annotation.GetMapping("/{id}")
                    Object detail(Long id) { return orderService.load(id); }
                }
                """);
        write("src/main/java/demo/OrderConsumer.java", """
                package demo;
                class OrderConsumer {
                    @org.springframework.kafka.annotation.KafkaListener(topics = "orders")
                    void consume(String payload) { orderService.accept(payload); }
                }
                """);
        write("src/main/java/demo/OrderRepository.java", """
                package demo;
                class OrderRepository {
                    Object load(Long id) { return jdbcTemplate.queryForList("select * from orders"); }
                }
                """);
        write("src/main/java/demo/SecurityConfig.java", """
                package demo;
                @org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
                class SecurityConfig {
                    Object filterChain(Object http) {
                        http.authorizeHttpRequests(auth -> auth.requestMatchers("/public/**").permitAll())
                            .csrf(csrf -> csrf.disable());
                        return http;
                    }
                }
                """);

        ReconSummary summary = buildIncremental(new ReconService(mapper));
        ProjectStructureProfile profile = summary.projectStructure();

        assertThat(profile.modules()).singleElement().satisfies(module -> {
            assertThat(module.path()).isEqualTo(".");
            assertThat(module.sourceFileCount()).isEqualTo(6);
            assertThat(module.javaMethodCount()).isEqualTo(4);
            assertThat(module.endpointCount()).isEqualTo(1);
        });
        assertThat(profile.entryPoints()).extracting(ProjectStructureProfile.FactGroup::kind)
                .contains("HTTP_GET", "KAFKA_LISTENER");
        assertThat(profile.securityMechanisms()).extracting(ProjectStructureProfile.FactGroup::kind)
                .contains("ROUTE_AUTHORIZATION", "PUBLIC_ROUTE", "METHOD_SECURITY", "CSRF_CONFIGURATION");
        assertThat(profile.dataAccess()).extracting(ProjectStructureProfile.FactGroup::kind).contains("JDBC");
        assertThat(profile.externalIntegrations()).extracting(ProjectStructureProfile.FactGroup::kind)
                .contains("KAFKA");
        assertThat(profile.configurationFiles()).extracting(ProjectStructureProfile.FactGroup::kind)
                .contains("BUILD_DESCRIPTOR", "APPLICATION_CONFIGURATION");
        assertThat(summary.frameworkFiles()).extracting(ReconFrameworkFile::path)
                .containsExactly("pom.xml", "src/main/resources/application.yml");
        assertThat(summary.frameworkFiles()).filteredOn(file -> file.path().endsWith("application.yml"))
                .singleElement().satisfies(file -> assertThat(file.content()).contains("name: orders"));
        assertThat(summary.frameworkFacts().modules()).containsExactly(".");
        assertThat(summary.frameworkFacts().entryPointTypes()).contains("HTTP_GET", "KAFKA_LISTENER");
        assertThat(summary.frameworkFacts().technology().securityFrameworks()).contains("Spring Security");
    }

    @Test
    void countsAllFactsWithoutRetainingLocationEvidence() {
        List<CodeChunk> chunks = new ArrayList<>();
        for (int index = 0; index < 20; index++) {
            CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "src/main/java/demo/Api" + index + ".java",
                    "Api" + index + "#load", "/items/" + index, 10, 12, "return service.load();",
                    "JAVA_METHOD", "", "@GetMapping", "load");
            chunk.setAnalysisScope(index < 7 ? AnalysisScope.CHANGED : AnalysisScope.IMPACTED);
            chunks.add(chunk);
        }

        ProjectStructureProfile profile = new ProjectStructureProfiler().profile(projectRoot, chunks);

        assertThat(profile.modules()).singleElement().satisfies(module -> {
            assertThat(module.sourceFileCount()).isEqualTo(20);
            assertThat(module.endpointCount()).isEqualTo(20);
            assertThat(module.changedChunkCount()).isEqualTo(7);
            assertThat(module.impactedChunkCount()).isEqualTo(13);
        });
        assertThat(profile.entryPoints()).singleElement().satisfies(group -> {
            assertThat(group.kind()).isEqualTo("HTTP_GET");
            assertThat(group.occurrenceCount()).isEqualTo(20);
        });
    }

    @Test
    void excludesTestGeneratedAndDependencySourcesFromChunksAndTechnologyFacts() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);

        write("src/main/java/demo/OrderService.java", """
                package demo;
                class OrderService {
                    void submit() { repository.save(); }
                    @Test void testOnlyUnsafeCall() { statement.execute(userInput); }
                }
                """);
        write("src/main/resources/application.yml", "spring.application.name: orders");
        write("src/test/java/demo/InsecureControllerTest.java", """
                package demo;
                @RestController class InsecureControllerTest {
                    @Test void allowsUnsafeSql() { statement.execute(userInput); }
                }
                """);
        write("src/test/resources/application.yml", "spring.security.enabled: false");
        write("target/generated-sources/demo/Generated.java",
                "package demo; class Generated { void unsafe() { statement.execute(input); } }");
        write("node_modules/example/index.js", "element.innerHTML = input;");

        ReconSummary summary = buildIncremental(new ReconService(mapper));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CodeChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        List<CodeChunk> indexed = captor.getValue();
        assertThat(summary.sourceFileCount()).isEqualTo(2);
        assertThat(indexed).extracting(CodeChunk::getFilePath)
                .containsOnly(
                        "src/main/java/demo/OrderService.java",
                        "src/main/resources/application.yml");
        assertThat(indexed).extracting(CodeChunk::getSymbolName)
                .doesNotContain("OrderService#testOnlyUnsafeCall");
        assertThat(summary.technologyProfile().securityFrameworks()).doesNotContain("Spring Security");
        assertThat(summary.technologyProfile().frameworks()).doesNotContain("Spring MVC");
    }

    @Test
    void indexesChunksWithoutVectorData() throws Exception {
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        write("src/main/java/demo/OrderService.java", """
                package demo;
                class OrderService { void submit() { repository.save(); } }
                """);

        buildIncremental(new ReconService(mapper));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<CodeChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(mapper).insertBatch(captor.capture());
        assertThat(captor.getValue()).allSatisfy(chunk -> assertThat(chunk.getContent()).isNotBlank());
    }

    @Test
    void persistsPromotedImpactScope() {
        UUID taskId = UUID.randomUUID();
        CodeChunkMapper mapper = mock(CodeChunkMapper.class);
        CodeChunk impacted = new CodeChunk(taskId, "demo/Service.java", "Service#load", null,
                1, 3, "return repository.load();", "JAVA_METHOD", "", "", "load");
        impacted.setId(2L);
        impacted.setAnalysisScope(AnalysisScope.CONTEXT);
        when(mapper.findByTaskId(taskId)).thenReturn(List.of(impacted));

        new ReconService(mapper)
                .promoteImpactScope(taskId, Set.of(2L));

        assertThat(impacted.getAnalysisScope()).isEqualTo(AnalysisScope.IMPACTED);
        verify(mapper).updateIncrementalMetadata(impacted);
    }

    private ReconSummary buildIncremental(ReconService service) throws Exception {
        UUID taskId = UUID.randomUUID();
        List<GitFileChange> changes = new ArrayList<>();
        try (var paths = Files.walk(projectRoot)) {
            for (Path file : paths.filter(Files::isRegularFile).toList()) {
                String relative = projectRoot.relativize(file).toString().replace('\\', '/');
                int lines = Math.max(1, Files.readString(file).split("\\R", -1).length);
                changes.add(new GitFileChange(taskId, null, relative, "ADD", lines, 0,
                        "", "1:" + lines, "added test source", false));
            }
        }
        return service.buildIndex(taskId, projectRoot, projectRoot, changes);
    }

    private void write(String relative, String content) throws Exception {
        Path file = projectRoot.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
