package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class FindingLocationResolverTest {

    @Test
    void usesValidatedModelLineAndOnlyShowsNearbyContext() {
        String content = IntStream.rangeClosed(1, 30)
                .mapToObj(line -> line == 16 ? "statement.execute(userSql);" : "line" + line + "();")
                .collect(java.util.stream.Collectors.joining("\n"));
        CodeChunk chunk = chunk(100, 129, content);
        LlmGateway.FindingProposal proposal = proposal(VulnerabilityType.SQL_INJECTION, 115, 115);

        FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, chunk);
        String context = FindingLocationResolver.formatContext(chunk, location, true);

        assertThat(location).isEqualTo(new FindingLocationResolver.Location(115, 115));
        assertThat(context).contains(">>>   115 | statement.execute(userSql);")
                .contains("    111 | line12();", "    119 | line20();")
                .doesNotContain("line1();", "line30();");
    }

    @Test
    void infersDangerousLineWhenModelLineIsMissingOrOutsideChunk() {
        CodeChunk chunk = chunk(70, 76, """
                public List<User> search(String name) {
                    String sql = "select * from users where name='" + name + "'";
                    audit(name);
                    return statement.executeQuery(sql);
                }
                """);
        LlmGateway.FindingProposal proposal = proposal(VulnerabilityType.SQL_INJECTION, 999, 999);

        FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, chunk);

        assertThat(location.startLine()).isEqualTo(73);
        assertThat(FindingLocationResolver.formatContext(chunk, location, true))
                .contains(">>>    73 |     return statement.executeQuery(sql);");
    }

    @Test
    void marksSemanticCallSiteAsEntryInsteadOfInferringAnUnrelatedControllerLine() {
        CodeChunk controller = new CodeChunk(UUID.randomUUID(), "LabScenarioController.java",
                "LabScenarioController#purchase", "/payments/purchase", 79, 85, """
                @PreAuthorize("hasAuthority('TRANSFER_CREATE')")
                @PostMapping("/payments/purchase")
                public TransactionResult purchase(PurchaseRequest request) {
                    CurrentUser loginUser = securityContext.currentUser();
                    accountService.assertAccountBelongsToUser(loginUser.userId(), request.accountNo());
                    return labScenarioService.purchase(request);
                }
                """, "JAVA_METHOD", "PurchaseRequest request", "@PostMapping", "purchase");
        controller.setId(1497L);
        CodeChunk service = new CodeChunk(UUID.randomUUID(), "LabScenarioService.java",
                "LabScenarioService#purchase", null, 86, 88, """
                BigDecimal total = request.quotedUnitPrice().multiply(BigDecimal.valueOf(request.quantity()));
                accountRepository.debit(request.accountNo(), total);
                return completed(total);
                """, "JAVA_METHOD", "PurchaseRequest request", "", "debit,completed");
        service.setId(1549L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.FINANCIAL_RISK, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "服务端直接信任 quotedUnitPrice", "服务端查询可信价格",
                1549L, List.of(1549L, 1497L), 86, 88);

        String evidence = FindingLocationResolver.formatEvidence(proposal,
                Map.of(1497L, controller, 1549L, service), Map.of(1497L, 84));

        assertThat(evidence)
                .contains("[漏洞位置] LabScenarioService.java:86-88")
                .contains("[调用入口] LabScenarioController.java:84")
                .contains("return labScenarioService.purchase(request);")
                .doesNotContain("[漏洞位置] LabScenarioController.java:82-83");
    }

    @Test
    void givesCriticTwentyLinesAroundPrimaryLocationInsteadOfFour() {
        String content = IntStream.rangeClosed(100, 159)
                .mapToObj(line -> line == 130 ? "statement.execute(userSql);" : "line" + line + "();")
                .collect(java.util.stream.Collectors.joining("\n"));
        CodeChunk chunk = chunk(100, 159, content);
        LlmGateway.FindingProposal proposal = proposal(VulnerabilityType.SQL_INJECTION, 130, 130);

        String evidence = FindingLocationResolver.formatCriticEvidence(
                proposal, Map.of(1L, chunk), Set.of(1L), Map.of());

        assertThat(evidence)
                .contains("[CRITIC_PRIMARY_CONTEXT]")
                .contains("    110 | line110();")
                .contains(">>>   130 | statement.execute(userSql);")
                .contains("    150 | line150();")
                .doesNotContain("line109();", "line151();");
    }

    @Test
    void givesCriticTwelveLinesAroundRelatedCallSite() {
        CodeChunk primary = chunk(1, 3, "start();\nstatement.execute(sql);\nfinish();");
        CodeChunk related = new CodeChunk(UUID.randomUUID(), "demo/Controller.java",
                "Controller#search", "/search", 200, 259,
                IntStream.rangeClosed(200, 259).mapToObj(line -> "line" + line + "();")
                        .collect(java.util.stream.Collectors.joining("\n")),
                "JAVA_METHOD", "String query", "", "search");
        related.setId(2L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "外部参数进入 executeQuery", "使用参数化查询",
                1L, List.of(1L, 2L), 2, 2);

        String evidence = FindingLocationResolver.formatCriticEvidence(
                proposal, Map.of(1L, primary, 2L, related), Set.of(1L, 2L), Map.of(2L, 230));

        assertThat(evidence)
                .contains("[CRITIC_ENTRY_EVIDENCE]")
                .contains("    218 | line218();")
                .contains(">>>   230 | line230();")
                .contains("    242 | line242();")
                .doesNotContain("line217();", "line243();");
    }

    @Test
    void capsCombinedCriticContextToAvoidUnboundedTokenGrowth() {
        Map<Long, CodeChunk> chunks = new java.util.LinkedHashMap<>();
        List<Long> ids = new java.util.ArrayList<>();
        Map<Long, Integer> callSites = new java.util.LinkedHashMap<>();
        String content = IntStream.rangeClosed(1, 60)
                .mapToObj(line -> "line" + line + "_" + "x".repeat(180) + "();")
                .collect(java.util.stream.Collectors.joining("\n"));
        for (long id = 1; id <= 7; id++) {
            CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "demo/Chunk" + id + ".java",
                    "Chunk" + id + "#run", id == 1 ? null : "/entry/" + id,
                    1, 60, content, "JAVA_METHOD", "", "", "run");
            chunk.setId(id);
            chunks.put(id, chunk);
            ids.add(id);
            if (id > 1) callSites.put(id, 30);
        }
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "外部参数进入 executeQuery", "使用参数化查询",
                1L, ids, 30, 30);

        String evidence = FindingLocationResolver.formatCriticEvidence(
                proposal, chunks, Set.copyOf(ids), callSites);

        assertThat(evidence.length()).isLessThanOrEqualTo(20_000);
        assertThat(evidence).contains("[CRITIC_CONTEXT_TRUNCATED]");
    }

    @Test
    void relocatesCriticLineThatDoesNotMatchStructuredRootCauseAndRole() {
        CodeChunk chunk = chunk(70, 74, """
                public List<User> search(String name) {
                    audit(name);
                    String sql = "select * from users where name='" + name + "'";
                    return statement.executeQuery(sql);
                }
                """);
        LlmGateway.FindingProposal proposal = proposal(VulnerabilityType.SQL_INJECTION, 71, 71);
        LlmGateway.CriticDecision decision = new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "外部参数进入动态查询", com.deepaudit.domain.FindingDeltaStatus.BASELINE,
                chunk.getId(), 71, 71, "UNSAFE_QUERY", "QUERY");

        assertThat(FindingLocationResolver.resolveCriticPrimary(
                proposal, decision, Map.of(chunk.getId(), chunk), Set.of(chunk.getId())))
                .get().satisfies(location -> {
                    assertThat(location.chunkId()).isEqualTo(chunk.getId());
                    assertThat(location.location()).isEqualTo(new FindingLocationResolver.Location(73, 73));
                });
    }

    private LlmGateway.FindingProposal proposal(VulnerabilityType type, Integer start, Integer end) {
        return new LlmGateway.FindingProposal(type, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "外部参数进入 executeQuery", "使用参数化查询",
                1L, List.of(1L), start, end);
    }

    private CodeChunk chunk(int start, int end, String content) {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "demo/UserService.java", "UserService#search", null,
                start, end, content, "JAVA_METHOD", "String name", "", "executeQuery");
        chunk.setId(1L);
        return chunk;
    }
}
