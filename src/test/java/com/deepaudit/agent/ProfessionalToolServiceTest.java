package com.deepaudit.agent;

import com.deepaudit.ai.AiProperties;
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
    private final AiProperties aiProperties = new AiProperties();
    private final ProfessionalToolService service = new ProfessionalToolService(
            symbolMapper, edgeMapper, flowMapper, methodChangeMapper, fileChangeMapper, aiProperties);
    private final UUID taskId = UUID.randomUUID();

    @BeforeEach
    void defaults() {
        aiProperties.setMaxObservationChars(4_000);
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
        assertThat(result.text()).contains("SEARCH_RESULT", "OrderMapper#selectById", "kind=MYBATIS_SQL")
                .doesNotContain("SELECT * FROM orders", "UNTRUSTED_CODE");
    }

    @Test
    void symbolSearchReturnsMetadataWithoutSource() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/orders", "service.load(id)");
        CodeChunk mapper = chunk(2L, "demo/OrderMapper.xml", "OrderMapper#selectById", null,
                "SELECT secret_value FROM orders");

        ToolResult result = service.searchSymbols(taskId, current, List.of(current, mapper),
                ToolArguments.of(Map.of("symbol", "selectById")), 5);

        assertThat(result.text()).contains("CHUNK_ID=2", "OrderMapper#selectById")
                .doesNotContain("SELECT secret_value FROM orders", "UNTRUSTED_CODE");
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
    void returnsCurrentChangeSummaryAndConfigurationIndexWithoutDuplicateDiffs() {
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

        ToolResult defaultResult = service.getChangeContext(taskId, current,
                List.of(current, config), ToolArguments.of(Map.of()), 5);
        ToolResult withConfiguration = service.getChangeContext(taskId, current,
                List.of(current, config), ToolArguments.of(Map.of("includeConfiguration", true)), 5);

        assertThat(defaultResult.text()).contains("CURRENT_CHANGE_SUMMARY", "currentDiffProvidedInTarget=true",
                        "GUARD_REMOVED", "移除了资源所有权校验")
                .doesNotContain("application.yml", "UNTRUSTED_DIFF", "checkOwner(id)");
        assertThat(withConfiguration.evidenceChunkIds()).containsExactly(1L);
        assertThat(withConfiguration.candidateChunkIds()).containsExactly(2L);
        assertThat(withConfiguration.text()).contains("CURRENT_CHANGE_SUMMARY", "FILE_CHANGE_INDEX",
                        "application.yml")
                .doesNotContain("UNTRUSTED_DIFF", "security.enabled: true", "security.enabled: false");
    }

    @Test
    void returnsUnifiedDiffForSelectedRelatedMethodAndKeepsItAsCandidate() {
        CodeChunk current = chunk(1L, "demo/Service.java", "Service#entry", null, "return checkOwner(id);");
        CodeChunk related = chunk(2L, "demo/Service.java", "Service#checkOwner", null, "return true;");
        SemanticMethodChange change = new SemanticMethodChange(taskId, SemanticChangeKind.GUARD_REMOVED,
                "checkOwner", "demo/Service.java", "demo/Service.java", "Service#checkOwner",
                "Service#checkOwner", 30, 34, 30, 33,
                "checkAuthenticated();\ncheckOwnership(id);\nreturn true;",
                "checkAuthenticated();\nreturn true;", "移除了对象归属校验");
        GitFileChange sameFile = new GitFileChange(taskId, "demo/Service.java", "demo/Service.java",
                "MODIFY", 0, 1, "31-31", "", "- checkOwnership(id);", false);
        when(methodChangeMapper.findByTaskId(taskId)).thenReturn(List.of(change));
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of(sameFile));

        ToolResult result = service.getChangeContext(taskId, current, List.of(current, related),
                ToolArguments.of(Map.of("selector", "checkOwner")), 5);

        assertThat(result.evidenceChunkIds()).containsExactly(1L);
        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("RELATED_METHOD_CHANGE", "CHUNK_IDS=[2]",
                        "<UNTRUSTED_DIFF>", "- B31 | checkOwnership(id);", "移除了对象归属校验")
                .doesNotContain("[FILE_CHANGE]");
    }

    @Test
    void returnsAtMostThreeFileHunksForExplicitFileSelector() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", null, "return ok();");
        CodeChunk config = chunk(2L, "application.yml", "application.yml#1", null, "security: false");
        String context = String.join("\n",
                "@@ base 1-1 target 1-1 @@", "- first-old", "+ first-new",
                "@@ base 10-10 target 10-10 @@", "- second-old", "+ second-new",
                "@@ base 20-20 target 20-20 @@", "- third-old", "+ third-new",
                "@@ base 30-30 target 30-30 @@", "- fourth-old", "+ fourth-new");
        GitFileChange configChange = new GitFileChange(taskId, "application.yml", "application.yml",
                "MODIFY", 4, 4, "1,10,20,30", "1,10,20,30", context, true);
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of(configChange));

        ToolResult result = service.getChangeContext(taskId, current, List.of(current, config),
                ToolArguments.of(Map.of("selector", "application.yml")), 5);

        assertThat(result.candidateChunkIds()).containsExactly(2L);
        assertThat(result.text()).contains("[FILE_CHANGE]", "returnedHunks=3", "totalHunks=4",
                        "first-new", "second-new", "third-new", "MORE_FILE_HUNKS")
                .doesNotContain("fourth-new");
    }

    @Test
    void appliesLimitAcrossMethodSummariesAndFileIndexesTogether() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", null, "return ok();");
        CodeChunk firstConfig = chunk(2L, "a.yml", "a.yml#1", null, "a: false");
        CodeChunk secondConfig = chunk(3L, "b.yml", "b.yml#1", null, "b: false");
        SemanticMethodChange currentChange = new SemanticMethodChange(taskId, SemanticChangeKind.METHOD_MODIFIED,
                "entry", "demo/Controller.java", "demo/Controller.java", "Controller#entry",
                "Controller#entry", 1, 3, 1, 3, "return old();", "return ok();", "修改返回值");
        GitFileChange first = new GitFileChange(taskId, "a.yml", "a.yml", "MODIFY",
                1, 1, "1", "1", "- a: true\n+ a: false", true);
        GitFileChange second = new GitFileChange(taskId, "b.yml", "b.yml", "MODIFY",
                1, 1, "1", "1", "- b: true\n+ b: false", true);
        when(methodChangeMapper.findByTaskId(taskId)).thenReturn(List.of(currentChange));
        when(fileChangeMapper.findByTaskId(taskId)).thenReturn(List.of(second, first));

        ToolResult result = service.getChangeContext(taskId, current,
                List.of(current, firstConfig, secondConfig),
                ToolArguments.of(Map.of("includeConfiguration", true)), 2);

        assertThat(result.text()).contains("CURRENT_CHANGE_SUMMARY", "a.yml")
                .doesNotContain("b.yml");
        assertThat(result.candidateChunkIds()).containsExactly(2L);
    }

    @Test
    void resolvesConnectedSqlAndReportsBindingIndicators() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/search", "service.search(input)");
        CodeChunk mapper = chunk(2L, "demo/UserMapper.xml", "UserMapper#search", null,
                """
                SELECT * FROM users WHERE name = ${name} AND tenant_id = #{tenantId}
                context-1
                context-2
                context-3
                context-4
                context-5
                TAIL_NOT_INCLUDED
                """);
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(edge(1L, 2L, 7, "input -> name")));

        ToolResult result = service.resolveDataAccess(taskId, current,
                List.of(current, mapper), ToolArguments.of(Map.of("depth", 2)), 5);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 2L);
        assertThat(result.text()).contains("RAW_SUBSTITUTION_${}", "BOUND_PARAMETER_#{}",
                        "OWNERSHIP_OR_TENANT_CONSTRAINT_INDICATOR", ">>>     1 |", "context-5")
                .doesNotContain("TAIL_NOT_INCLUDED");
    }

    @Test
    void matchesEndpointSecurityPolicyAndLeavesUnrelatedPolicyAsCandidate() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/orders/42", "return service.load(42);");
        CodeChunk matched = chunk(2L, "demo/SecurityConfig.java", "SecurityConfig#chain", null,
                """
                http.authorizeHttpRequests(a -> a.requestMatchers("/orders/**").authenticated());
                context-1
                context-2
                context-3
                context-4
                context-5
                TAIL_NOT_INCLUDED
                """);
        CodeChunk unrelated = chunk(3L, "demo/AdminSecurity.java", "AdminSecurity#chain", null,
                "http.authorizeHttpRequests(a -> a.requestMatchers(\"/admin/**\").hasRole(\"ADMIN\"));");

        ToolResult result = service.inspectSecurityPolicy(taskId, current,
                List.of(current, matched, unrelated), ToolArguments.of(Map.of()), 5);

        assertThat(result.evidenceChunkIds()).contains(1L, 2L);
        assertThat(result.candidateChunkIds()).contains(3L);
        assertThat(result.text()).contains("VERIFIED_POLICY_RELATION", "AUTHENTICATED",
                        "UNVERIFIED_CANDIDATE", ">>>     1 |", "context-5")
                .doesNotContain("TAIL_NOT_INCLUDED");
    }

    @Test
    void traceValueReturnsCallSiteWithFiveLinesOfContext() {
        CodeChunk current = chunk(1L, "demo/Service.java", "Service#entry", null, String.join("\n",
                "outside-before", "before-5", "before-4", "before-3", "before-2", "before-1",
                "call(value);", "after-1", "after-2", "after-3", "after-4", "after-5", "outside-after"));
        CodeChunk callee = chunk(2L, "demo/Repository.java", "Repository#call", null, "return value;");
        when(edgeMapper.findByTaskId(taskId)).thenReturn(List.of(edge(1L, 2L, 7, "value -> value")));

        ToolResult result = service.traceValue(taskId, current, List.of(current, callee),
                ToolArguments.of(Map.of("variable", "value", "depth", 2)),
                5, VulnerabilityType.SQL_INJECTION);

        assertThat(result.text()).contains("ARGUMENT_MAPPING", "before-5", ">>>     7 | call(value);", "after-5")
                .doesNotContain("outside-before", "outside-after");
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
                        "cursor", Long.parseLong(pageOne.nextCursor()))), 1);

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
    void mergesOverlappingCodeSearchMatchesIntoOneWindow() {
        CodeChunk current = chunk(1L, "src/main/java/demo/SecurityConfig.java",
                "SecurityConfig#api", null, String.join("\n",
                "start", "permitAll();", "permitAll();", "permitAll();", "end"));

        ToolResult result = service.searchCode(taskId, current, List.of(current),
                ToolArguments.of(Map.of("query", "permitAll", "scope", "PROJECT", "contextLines", 1)), 10);

        assertThat(result.truncated()).isFalse();
        assertThat(result.text()).contains(">>>     2 | permitAll();", ">>>     3 | permitAll();",
                        ">>>     4 | permitAll();")
                .containsOnlyOnce("CHUNK_ID=1");
    }

    @Test
    void advancesCursorOnlyPastItemsActuallySerializedWithinObservationBudget() {
        aiProperties.setMaxObservationChars(1_000);
        CodeChunk current = chunk(1L, "src/main/java/demo/Controller.java",
                "Controller#entry", null, "return ok();");
        CodeChunk first = chunk(2L, "src/main/java/demo/A.java", "A#match", null,
                "permitAll " + "a".repeat(700));
        CodeChunk second = chunk(3L, "src/main/java/demo/B.java", "B#match", null,
                "permitAll " + "b".repeat(700));
        CodeChunk third = chunk(4L, "src/main/java/demo/C.java", "C#match", null,
                "permitAll " + "c".repeat(700));
        List<CodeChunk> chunks = List.of(current, first, second, third);

        ToolResult pageOne = service.searchCode(taskId, current, chunks,
                ToolArguments.of(Map.of("query", "permitAll", "scope", "PROJECT")), 10);
        ToolResult pageTwo = service.searchCode(taskId, current, chunks,
                ToolArguments.of(Map.of("query", "permitAll", "scope", "PROJECT",
                        "cursor", Long.parseLong(pageOne.nextCursor()))), 10);

        assertThat(pageOne.candidateChunkIds()).containsExactly(2L);
        assertThat(pageOne.nextCursor()).isEqualTo("1");
        assertThat(pageOne.text()).contains("ITEM_TRUNCATED");
        assertThat(pageTwo.candidateChunkIds()).containsExactly(3L);
        assertThat(pageTwo.nextCursor()).isEqualTo("2");
    }

    @Test
    void keepsSearchPaginationBelowTheGlobalToolResultLimit() {
        aiProperties.setMaxObservationChars(40_000);
        CodeChunk current = chunk(1L, "src/main/java/demo/Controller.java",
                "Controller#entry", null, "return ok();");
        CodeChunk first = chunk(2L, "src/main/java/demo/A.java", "A#match", null,
                "permitAll " + "a".repeat(12_000));
        CodeChunk second = chunk(3L, "src/main/java/demo/B.java", "B#match", null,
                "permitAll " + "b".repeat(12_000));
        CodeChunk third = chunk(4L, "src/main/java/demo/C.java", "C#match", null,
                "permitAll " + "c".repeat(12_000));

        ToolResult result = service.searchCode(taskId, current, List.of(current, first, second, third),
                ToolArguments.of(Map.of("query", "permitAll", "scope", "PROJECT")), 10);

        assertThat(result.text()).hasSizeLessThan(ToolResult.MAX_TEXT_CHARS)
                .contains("ITEM_TRUNCATED")
                .doesNotContain("TOOL_RESULT_TRUNCATED");
        assertThat(result.candidateChunkIds()).containsExactlyInAnyOrder(2L, 3L);
        assertThat(result.nextCursor()).isEqualTo("2");
    }

    @Test
    void evaluatesAllSecurityPoliciesBeforeApplyingLimit() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", "/orders/42", "return ok();");
        List<CodeChunk> chunks = new java.util.ArrayList<>();
        chunks.add(current);
        for (long id = 2; id <= 5; id++) {
            chunks.add(chunk(id, "demo/A" + id + "Security.java", "Security#chain" + id, null,
                    "http.authorizeHttpRequests(a -> a.requestMatchers(\"/unrelated/" + id
                            + "\").authenticated());"));
        }
        CodeChunk matched = chunk(6L, "demo/ZSecurity.java", "Security#orders", null,
                "http.authorizeHttpRequests(a -> a.requestMatchers(\"/orders/**\").authenticated());");
        chunks.add(matched);

        ToolResult result = service.inspectSecurityPolicy(taskId, current, chunks,
                ToolArguments.of(Map.of()), 1);

        assertThat(result.evidenceChunkIds()).containsExactlyInAnyOrder(1L, 6L);
        assertThat(result.candidateChunkIds()).isEmpty();
        assertThat(result.text()).contains("endpoint=/orders/42", "CHUNK_ID=6")
                .doesNotContain("CHUNK_ID=2");
    }

    @Test
    void rejectsInvalidCallGraphDirectionInsteadOfFallingBackToBoth() {
        CodeChunk current = chunk(1L, "demo/Controller.java", "Controller#entry", null, "return ok();");

        ToolResult result = service.exploreCallGraph(taskId, current, List.of(current),
                ToolArguments.of(Map.of("direction", "SIDEWAYS")), 5);

        assertThat(result.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(result.text()).contains("CALLERS", "CALLEES", "BOTH");
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

    @Test
    void rejectsCodeSearchQueriesLongerThanFiveHundredCharacters() {
        CodeChunk current = chunk(1L, "src/main/java/demo/Controller.java",
                "Controller#entry", null, "return ok();");

        ToolResult result = service.searchCode(taskId, current, List.of(current),
                ToolArguments.of(Map.of("query", "x".repeat(501))), 5);

        assertThat(result.status()).isEqualTo(ToolResult.Status.INVALID);
        assertThat(result.text()).contains("最长为 500 个字符");
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
