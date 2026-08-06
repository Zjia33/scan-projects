package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
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
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
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
    void prefersActualUnsafeValueUseWhenModelMarksOnlyPreconditionChecks() {
        CodeChunk chunk = chunk(78, 91, """
                public TransactionResult purchase(PurchaseRequest request) {
                    if (request == null
                            || request.quotedUnitPrice() == null
                            || request.quotedUnitPrice().signum() <= 0
                            || request.quantity() <= 0) {
                        throw new IllegalArgumentException("Invalid purchase request");
                    }
                    if (!PRODUCT_CATALOG.containsKey(request.productCode())) {
                        throw new IllegalArgumentException("Invalid purchase request");
                    }
                    BigDecimal total = request.quotedUnitPrice().multiply(BigDecimal.valueOf(request.quantity()));
                    accountRepository.debit(request.accountNo(), total);
                    return completed(total);
                }
                """);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "购买接口接受客户端报价，绕过服务端目录价格校验",
                "请求仅检查 quotedUnitPrice 非空和正数，未与 PRODUCT_CATALOG 目录价格比对，"
                        + "随后使用 quotedUnitPrice 计算扣款金额。",
                "使用服务端目录价格", 1L, List.of(1L), 78, 82);

        FindingLocationResolver.Location location = FindingLocationResolver.resolve(proposal, chunk);

        assertThat(location).isEqualTo(new FindingLocationResolver.Location(88, 88));
        assertThat(FindingLocationResolver.formatContext(chunk, location, true))
                .contains(">>>    88 |     BigDecimal total = request.quotedUnitPrice().multiply")
                .doesNotContain(">>>    78 | public TransactionResult purchase");
    }

    @Test
    void omitsRelatedChunksThatHaveNoRenderableSource() {
        CodeChunk primary = chunk(70, 76, """
                public List<User> search(String name) {
                    String sql = "select * from users where name='" + name + "'";
                    audit(name);
                    return statement.executeQuery(sql);
                }
                """);
        CodeChunk empty = new CodeChunk(UUID.randomUUID(), "deleted/LegacyService.java", "LegacyService#run",
                null, 80, 80, "   \n", "JAVA_METHOD", "", "", "run");
        empty.setId(2L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "外部参数进入查询", "使用参数化查询", 1L, List.of(1L, 2L), 73, 73);

        String evidence = FindingLocationResolver.formatEvidence(proposal,
                Map.of(1L, primary, 2L, empty), Map.of());

        assertThat(evidence).contains("[漏洞位置] demo/UserService.java:73")
                .doesNotContain("LegacyService.java", "[关联证据]");
    }

    @Test
    void keepsRelatedSourceWithoutInventingAnExactCallSite() {
        CodeChunk primary = chunk(70, 76, """
                public List<User> search(String name) {
                    String sql = "select * from users where name='" + name + "'";
                    audit(name);
                    return statement.executeQuery(sql);
                }
                """);
        CodeChunk related = new CodeChunk(UUID.randomUUID(), "controller/SearchController.java", "SearchController#search",
                "/search", 200, 202, "return service.search(name);\n", "JAVA_METHOD", "", "", "search");
        related.setId(2L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "动态 SQL 注入", "外部参数进入查询", "使用参数化查询", 1L, List.of(1L, 2L), 73, 73);

        String evidence = FindingLocationResolver.formatEvidence(proposal,
                Map.of(1L, primary, 2L, related), Map.of(2L, 80));

        assertThat(evidence).contains("[漏洞位置] demo/UserService.java:73")
                .contains("[关联证据] controller/SearchController.java:200-202")
                .contains("return service.search(name);")
                .doesNotContain("[调用入口] controller/SearchController.java:80");
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
