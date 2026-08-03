package com.deepaudit.agent;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.GitFileChange;
import com.deepaudit.domain.SecurityFlow;
import com.deepaudit.domain.SemanticCallEdge;
import com.deepaudit.domain.SemanticChangeKind;
import com.deepaudit.domain.SemanticMethodChange;
import com.deepaudit.domain.VulnerabilityType;
import com.deepaudit.mapper.GitFileChangeMapper;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticMethodChangeMapper;
import com.deepaudit.mapper.SemanticSymbolMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProfessionalToolServiceTest {
    private final SemanticSymbolMapper symbolMapper = mock(SemanticSymbolMapper.class);
    private final SemanticCallEdgeMapper edgeMapper = mock(SemanticCallEdgeMapper.class);
    private final SecurityFlowMapper flowMapper = mock(SecurityFlowMapper.class);
    private final SemanticMethodChangeMapper methodChangeMapper = mock(SemanticMethodChangeMapper.class);
    private final GitFileChangeMapper fileChangeMapper = mock(GitFileChangeMapper.class);
    private final ProfessionalToolService service = new ProfessionalToolService(
            symbolMapper, edgeMapper, flowMapper, methodChangeMapper, fileChangeMapper);
    private final UUID taskId = UUID.randomUUID();

    @BeforeEach
    void defaults() {
        when(symbolMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(flowMapper.findByTaskAndChunk(taskId, 1L)).thenReturn(List.of());
        when(methodChangeMapper.findByTaskId(taskId)).thenReturn(List.of());
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of());
    }

    @Test
    void searchesSymbolsDeterministicallyAndKeepsOtherChunksAsCandidates() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/orders", "service.load(id)");
        CodeChunk mapper = chunk(2L, "demo/OrderMapper.xml", "OrderMapper#selectById", null,
                "SELECT * FROM orders WHERE id = #{id}");

        ToolResult result = service.searchSymbols(taskId, current, List.of(current, mapper),
                ToolArguments.of(Map.of("symbol", "selectById", "kind", "MYBATIS")), 5);

        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("SEARCH_RESULT", "OrderMapper#selectById", "UNTRUSTED_CODE");
    }

    @Test
    void exploresDirectionalCallGraphWithArgumentMappings() {
        CodeChunk controller = chunk(1L, "demo/Controller.java", "Controller#entry", "/orders", "service.load(id)");
        CodeChunk serviceChunk = chunk(2L, "demo/OrderService.java", "OrderService#load", null,
                "return mapper.select(id)");
        CodeChunk mapper = chunk(3L, "demo/OrderMapper.xml", "OrderMapper#select", null,
                "SELECT * FROM orders WHERE id = #{id}");
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(
                edge(1L, 2L, 8, "id -> id"), edge(2L, 3L, 15, "id -> id")));

        ToolResult result = service.exploreCallGraph(taskId, controller,
                List.of(controller, serviceChunk, mapper),
                ToolArguments.of(Map.of("direction", "CALLEES", "depth", 3, "targetChunkId", 3)), 5);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L, 3L);
        assertThat(result.text()).contains("direction=CALLEES", "depth=2", "args=id -> id");
    }

    @Test
    void returnsMethodAndConfigurationChangeContextWithSeparateEvidenceLevels() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/orders", "return service.load(id);");
        CodeChunk config = chunk(2L, "application.yml", "application.yml#1", null, "security.enabled: false");
        SemanticMethodChange change = new SemanticMethodChange(taskId, SemanticChangeKind.GUARD_REMOVED,
                "entry", "demo/Controller.java", "demo/Controller.java", "Controller#entry",
                "Controller#entry", 3, 6, 3, 5, "checkOwner(id); return load(id);",
                "return load(id);", "移除了资源所有权校验");
        GitFileChange configChange = new GitFileChange(taskId, "application.yml", "application.yml",
                "MODIFY", 1, 1, "1-1", "1-1", "- security.enabled: true\n+ security.enabled: false", true);
        when(methodChangeMapper.findByTaskId(taskId)).thenReturn(List.of(change));
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of(configChange));

        ToolResult result = service.getChangeContext(taskId, current,
                List.of(current, config), ToolArguments.of(Map.of("includeConfiguration", true)), 5);

        assertThat(result.evidenceChunkIds()).contains(1L);
        assertThat(result.candidateChunkIds()).contains(2L);
        assertThat(result.text()).contains("GUARD_REMOVED", "移除了资源所有权校验", "UNTRUSTED_DIFF");
    }

    @Test
    void resolvesConnectedSqlAndReportsBindingIndicators() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/search", "service.search(input)");
        CodeChunk mapper = chunk(2L, "demo/UserMapper.xml", "UserMapper#search", null,
                "SELECT * FROM users WHERE name = ${name} AND tenant_id = #{tenantId}");
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(edge(1L, 2L, 7, "input -> name")));

        ToolResult result = service.resolveDataAccess(taskId, current,
                List.of(current, mapper), ToolArguments.of(Map.of("depth", 2)), 5);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L);
        assertThat(result.text()).contains("RAW_SUBSTITUTION_${}", "BOUND_PARAMETER_#{}",
                "OWNERSHIP_OR_TENANT_CONSTRAINT_INDICATOR");
    }

    @Test
    void matchesEndpointSecurityPolicyAndLeavesUnrelatedPolicyAsCandidate() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/orders/42", "return service.load(42);");
        CodeChunk matched = chunk(2L, "demo/SecurityConfig.java", "SecurityConfig#chain", null,
                "http.authorizeHttpRequests(a -> a.requestMatchers(\"/orders/**\").authenticated());");
        CodeChunk unrelated = chunk(3L, "demo/AdminSecurity.java", "AdminSecurity#chain", null,
                "http.authorizeHttpRequests(a -> a.requestMatchers(\"/admin/**\").hasRole(\"ADMIN\"));");

        ToolResult result = service.inspectSecurityPolicy(taskId, current,
                List.of(current, matched, unrelated), ToolArguments.of(Map.of()), 5);

        assertThat(result.evidenceChunkIds()).contains(1L, 2L);
        assertThat(result.candidateChunkIds()).contains(3L);
        assertThat(result.text()).contains("VERIFIED_POLICY_RELATION", "AUTHENTICATED", "UNVERIFIED_CANDIDATE");
    }

    @Test
    void tracesTargetedValueThroughPersistedSecurityFlow() {
        CodeChunk current = chunk(1L, "demo/SearchController.java", "SearchController#search", "/search", "service.search(input)");
        SecurityFlow flow = new SecurityFlow(taskId, VulnerabilityType.SQL_INJECTION, UUID.randomUUID(),
                UUID.randomUUID(), 1L, "HTTP parameter input", "Statement.execute(sql)",
                "未发现参数化处理", "input -> service.search -> Statement.execute", "1,2",
                Confidence.HIGH, 1, 0);
        when(flowMapper.findByTaskAndChunk(taskId, 1L)).thenReturn(List.of(flow));

        ToolResult result = service.traceValue(taskId, current, List.of(current),
                ToolArguments.of(Map.of("variable", "input", "sink", "Statement.execute")),
                5, VulnerabilityType.SQL_INJECTION);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L);
        assertThat(result.text()).contains("VALUE_TRACE", "HTTP parameter input", "Statement.execute(sql)");
    }

    @Test
    void searchesCodeWithLineSnippetsAndCursorPagination() {
        CodeChunk current = chunk(1L, "src/main/java/demo/Controller.java",
                "Controller#entry", "/orders", "return service.load(id);");
        CodeChunk first = chunk(2L, "src/main/java/demo/SecurityConfig.java",
                "SecurityConfig#api", null, """
                http.authorizeHttpRequests(auth -> auth
                    .requestMatchers("/public/**").permitAll()
                    .anyRequest().authenticated());
                """);
        CodeChunk second = chunk(3L, "src/main/java/demo/AdminSecurity.java",
                "AdminSecurity#api", null, """
                http.authorizeHttpRequests(auth -> auth
                    .requestMatchers("/health").permitAll()
                    .anyRequest().hasRole("ADMIN"));
                """);

        ToolResult pageOne = service.searchCode(taskId, current,
                List.of(current, first, second), ToolArguments.of(Map.of(
                        "query", "permitAll", "scope", "PROJECT", "contextLines", 1)), 1);
        ToolResult pageTwo = service.searchCode(taskId, current,
                List.of(current, first, second), ToolArguments.of(Map.of(
                        "query", "permitAll", "scope", "PROJECT", "contextLines", 1,
                        "cursor", pageOne.nextCursor())), 1);

        assertThat(pageOne.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(pageOne.truncated()).isTrue();
        assertThat(pageOne.nextCursor()).isEqualTo("1");
        assertThat(pageOne.candidateChunkIds()).hasSize(1);
        assertThat(pageOne.text()).contains("CODE_SEARCH", ">>>", "permitAll");
        assertThat(pageTwo.truncated()).isFalse();
        assertThat(pageTwo.nextCursor()).isNull();
        assertThat(pageTwo.candidateChunkIds()).hasSize(1)
                .doesNotContainAnyElementsOf(pageOne.candidateChunkIds());
    }

    @Test
    void treatsRegexSyntaxAsLiteralText() {
        CodeChunk current = chunk(1L, "src/main/java/demo/Controller.java",
                "Controller#entry", "/orders", "String marker = \"(a+)+\";");

        ToolResult result = service.searchCode(taskId, current,
                List.of(current), ToolArguments.of(Map.of(
                        "query", "(a+)+", "scope", "PROJECT")), 5);

        assertThat(result.status()).isEqualTo(ToolResult.Status.OK);
        assertThat(result.text()).contains(">>>", "(a+)+");
    }

    private SemanticCallEdge edge(long caller, long callee, int line, String mapping) {
        return new SemanticCallEdge(taskId, UUID.randomUUID(), UUID.randomUUID(), caller, callee, line,
                "call", "call(value)", "JAVA_CALL", Confidence.HIGH, "精确符号解析", mapping);
    }

    private CodeChunk chunk(long id, String path, String symbol, String endpoint, String content) {
        CodeChunk chunk = new CodeChunk(taskId, path, symbol, endpoint, 1, 20, content,
                path.endsWith(".xml") ? "MYBATIS_SQL" : "JAVA_METHOD", "", "", "");
        chunk.setId(id);
        return chunk;
    }
}
