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
                VulnerabilityType.VALIDATION_BYPASS, Severity.HIGH, Confidence.HIGH,
                "客户端报价被用于扣款", "服务端直接信任 quotedUnitPrice", "服务端查询可信价格",
                1549L, List.of(1549L, 1497L), 86, 88);

        String evidence = FindingLocationResolver.formatEvidence(proposal,
                Map.of(1497L, controller, 1549L, service), Map.of(1497L, 84));

        assertThat(evidence)
                .contains("[漏洞根因] LabScenarioService.java:86-88")
                .contains("[调用入口] LabScenarioController.java:84")
                .contains("return labScenarioService.purchase(request);")
                .doesNotContain("[漏洞根因] LabScenarioController.java:82-83");
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
    void packagesLocationReferencesWithoutRepeatingOverlappingSourceLines() {
        CodeChunk chunk = chunk(70, 74, """
                public void transfer(Command command) {
                    authorization.check(command);
                    accountRepository.debit(command.accountNo(), command.amount());
                    audit.record(command);
                }
                """);
        chunk.setId(901L);
        LlmGateway.LocationCandidate first = new LlmGateway.LocationCandidate(
                "901:71-72", 901L, chunk.getFilePath(), chunk.getSymbolName(), 71, 72,
                "authorization.check(command);", List.of("SECURITY_BOUNDARY"),
                List.of("ROOT_CAUSE"), "CHANGED");
        LlmGateway.LocationCandidate second = new LlmGateway.LocationCandidate(
                "901:72-73", 901L, chunk.getFilePath(), chunk.getSymbolName(), 72, 73,
                "accountRepository.debit(command.accountNo(), command.amount());",
                List.of("DANGEROUS_OPERATION"), List.of("IMPACT"), "CHANGED");

        FindingLocationResolver.CriticEvidencePackage evidence =
                FindingLocationResolver.formatCriticEvidencePackage(
                        Map.of(chunk.getId(), chunk), List.of(first, second));

        assertThat(evidence.candidates()).containsExactly(first, second);
        assertThat(evidence.text()).contains(first.candidateId(), second.candidateId())
                .contains("<UNTRUSTED_CODE>", "</UNTRUSTED_CODE>")
                .contains("accountRepository.debit");
        assertThat(evidence.text().indexOf("accountRepository.debit"))
                .isEqualTo(evidence.text().lastIndexOf("accountRepository.debit"));
        assertThat(evidence.text().length()).isLessThanOrEqualTo(20_000);
    }

    @Test
    void relocatesSqlInjectionFromExecutionSinkToUnsafeQueryConstruction() {
        CodeChunk chunk = chunk(70, 74, """
                public List<User> search(String name) {
                    audit(name);
                    String sql = "select * from users where name='" + name + "'";
                    return statement.executeQuery(sql);
                }
                """);
        LlmGateway.FindingProposal proposal = proposal(VulnerabilityType.SQL_INJECTION, 71, 71);
        LlmGateway.CriticDecision decision = new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "外部参数进入动态查询", com.deepaudit.domain.FindingDeltaStatus.NEW,
                chunk.getId(), 71, 71, "UNSAFE_QUERY", "QUERY", null,
                LlmGateway.CriticVerdict.CONFIRMED, List.of());

        assertThat(FindingLocationResolver.resolveCriticPrimary(
                proposal, decision, Map.of(chunk.getId(), chunk), Set.of(chunk.getId())))
                .get().satisfies(location -> {
                    assertThat(location.chunkId()).isEqualTo(chunk.getId());
                    assertThat(location.location()).isEqualTo(new FindingLocationResolver.Location(72, 72));
                    assertThat(location.locationKind()).isEqualTo("ROOT_CAUSE");
                });
    }

    @Test
    void acceptsHardcodedSecretAtConfigurationDefinitionInsteadOfAuthorizationLocation() {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "src/main/resources/application.yml",
                "application.yml#part-1", null, 20, 21,
                "spring.datasource.password: committed-value\nserver.port: 8080",
                "TEXT_YML", "", "", "");
        chunk.setId(88L);
        List<LlmGateway.LocationCandidate> candidates = FindingLocationResolver.locationCandidates(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, Map.of(88L, chunk), Set.of(88L));
        LlmGateway.LocationCandidate secret = candidates.stream()
                .filter(candidate -> candidate.roles().contains("SECRET_DEFINITION"))
                .findFirst().orElseThrow();
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, Severity.HIGH, Confidence.HIGH,
                "配置中包含硬编码密码", "Target 新增了密码字面量", "使用 Secret 管理服务",
                88L, List.of(88L), 20, 20);
        LlmGateway.CriticDecision decision = new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "配置行直接定义了凭据", com.deepaudit.domain.FindingDeltaStatus.NEW,
                88L, 20, 20, "HARDCODED_SECRET", "SECRET_DEFINITION", secret.candidateId(),
                LlmGateway.CriticVerdict.CONFIRMED, List.of());

        assertThat(FindingLocationResolver.resolveCriticPrimary(
                proposal, decision, Map.of(88L, chunk), Set.of(88L)))
                .get().satisfies(location -> {
                    assertThat(location.chunkId()).isEqualTo(88L);
                    assertThat(location.location()).isEqualTo(new FindingLocationResolver.Location(20, 20));
                });
    }

    @Test
    void excludesImportsAndCommentsFromFileLevelLocationCandidates() {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "SensitiveDisclosureService.java",
                "SensitiveDisclosureService.java#changed-lines-1-14", null, 1, 14, """
                package com.example.bank.service;

                import java.io.PrintWriter;

                public class SensitiveDisclosureService {
                    /*
                    LOGGER.info("Withdrawal OTP issued: otp={}", otp);
                    */
                    // LOGGER.info("Withdrawal OTP issued: otp={}", otp);
                    public void issueWithdrawalOtp() {
                        String otp = generateOtp();
                        LOGGER.info("Withdrawal OTP issued: otp={}", otp);
                    }
                }
                """, "JAVA_CHANGE", "", "", "");
        chunk.setId(41L);

        List<LlmGateway.LocationCandidate> candidates = FindingLocationResolver.locationCandidates(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, Map.of(41L, chunk), Set.of(41L));

        assertThat(candidates)
                .noneMatch(candidate -> candidate.source().startsWith("package "))
                .noneMatch(candidate -> candidate.source().startsWith("import "))
                .noneMatch(candidate -> candidate.source().startsWith("//"))
                .anySatisfy(candidate -> {
                    assertThat(candidate.startLine()).isEqualTo(12);
                    assertThat(candidate.source()).contains("LOGGER.info");
                    assertThat(candidate.roles()).contains("DATA_OUTPUT");
                });
        assertThat(FindingLocationResolver.infer(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE,
                "LOGGER.info 明文记录 Withdrawal OTP", chunk))
                .isEqualTo(new FindingLocationResolver.Location(12, 12));

        LlmGateway.FindingProposal staleProposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, Severity.HIGH, Confidence.HIGH,
                "OTP 明文写入日志", "LOGGER.info 记录完整 OTP", "日志中移除 OTP",
                41L, List.of(41L), 3, 3);
        assertThat(FindingLocationResolver.formatEvidence(staleProposal, Map.of(41L, chunk)))
                .contains("[漏洞根因] SensitiveDisclosureService.java:12")
                .contains(">>>    12 |         LOGGER.info")
                .doesNotContain(">>>     3 | import java.io.PrintWriter;");
    }

    @Test
    void excludesFieldsAndConstructorParametersFromFallbackLocationCandidates() {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "SensitiveDisclosureController.java",
                "SensitiveDisclosureController.java#changed-lines-17-21", null, 17, 21, """
                private final SensitiveDisclosureService disclosureService;
                private final OwnerContext ownerContext;
                SensitiveDisclosureService disclosureService,
                OwnerContext ownerContext)
                return disclosureService.findCustomerSecurityRecord(userId);
                """, "JAVA_CHANGE", "", "", "");
        chunk.setId(43L);

        List<LlmGateway.LocationCandidate> candidates = FindingLocationResolver.locationCandidates(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, Map.of(43L, chunk), Set.of(43L));

        assertThat(candidates)
                .noneMatch(candidate -> candidate.source().contains("private final"))
                .noneMatch(candidate -> candidate.source().equals("SensitiveDisclosureService disclosureService,"))
                .noneMatch(candidate -> candidate.source().equals("OwnerContext ownerContext)"))
                .anySatisfy(candidate -> {
                    assertThat(candidate.startLine()).isEqualTo(21);
                    assertThat(candidate.source()).contains("findCustomerSecurityRecord");
                    assertThat(candidate.roles()).contains("DATA_OUTPUT");
                });
    }

    @Test
    void rejectsModelDeclaredRoleWhenSourceLineHasNoActualSecurityRole() {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "SensitiveDisclosureController.java",
                "SensitiveDisclosureController.java#changed-lines-21-21", null, 21, 21,
                "private final SensitiveDisclosureService disclosureService;",
                "JAVA_CHANGE", "", "", "");
        chunk.setId(44L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.AUTHORIZATION, Severity.HIGH, Confidence.HIGH,
                "对象级授权缺失", "接口未校验目标资源归属", "增加对象归属校验",
                44L, List.of(44L), 21, 21);
        LlmGateway.LocationCandidate field = new LlmGateway.LocationCandidate(
                "44:21-21", 44L, chunk.getFilePath(), chunk.getSymbolName(), 21, 21,
                chunk.getContent(), List.of(), List.of("SUPPORTING"), "CHANGED");
        LlmGateway.CriticDecision decision = new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "模型错误地把依赖字段当作数据访问",
                com.deepaudit.domain.FindingDeltaStatus.NEW,
                44L, 21, 21, "MISSING_AUTHORIZATION_CHECK", "DATA_ACCESS", field.candidateId(),
                LlmGateway.CriticVerdict.CONFIRMED, List.of());

        FindingLocationResolver.LocationResolution resolution = FindingLocationResolver.resolveCriticLocation(
                proposal, decision, Map.of(44L, chunk), Set.of(44L), List.of(field));

        assertThat(resolution.status()).isEqualTo(FindingLocationResolver.LocationStatus.UNRESOLVED);
        assertThat(resolution.resolved()).isEmpty();
    }

    @Test
    void rejectsStaleImportCandidateAndRelocatesToVerifiedLoggingSink() {
        CodeChunk chunk = new CodeChunk(UUID.randomUUID(), "SensitiveDisclosureService.java",
                "SensitiveDisclosureService.java#changed-lines-1-6", null, 1, 6, """
                package com.example.bank.service;

                import java.io.PrintWriter;

                String otp = generateOtp();
                LOGGER.info("Withdrawal OTP issued: otp={}", otp);
                """, "JAVA_CHANGE", "", "", "");
        chunk.setId(42L);
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE, Severity.HIGH, Confidence.HIGH,
                "OTP 明文写入日志", "LOGGER.info 记录完整 OTP", "日志中移除 OTP",
                42L, List.of(42L), 3, 3);
        List<LlmGateway.LocationCandidate> candidates = List.of(
                new LlmGateway.LocationCandidate("42:3-3", 42L, chunk.getFilePath(), chunk.getSymbolName(),
                        3, 3, "import java.io.PrintWriter;", List.of("DATA_OUTPUT"),
                        List.of("ROOT_CAUSE"), "CHANGED"),
                new LlmGateway.LocationCandidate("42:6-6", 42L, chunk.getFilePath(), chunk.getSymbolName(),
                        6, 6, "LOGGER.info(\"Withdrawal OTP issued: otp={}\", otp);",
                        List.of("DATA_OUTPUT"), List.of("ROOT_CAUSE"), "CHANGED"));
        LlmGateway.CriticDecision decision = new LlmGateway.CriticDecision(
                true, Confidence.HIGH, "日志输出泄露 OTP", com.deepaudit.domain.FindingDeltaStatus.NEW,
                42L, 3, 3, "UNSAFE_DATA_EXPOSURE", "DATA_OUTPUT", "42:3-3",
                LlmGateway.CriticVerdict.CONFIRMED, List.of());

        FindingLocationResolver.LocationResolution resolution =
                FindingLocationResolver.resolveCriticLocation(
                        proposal, decision, Map.of(42L, chunk), Set.of(42L), candidates);

        assertThat(resolution.status()).isEqualTo(FindingLocationResolver.LocationStatus.NORMALIZED);
        assertThat(resolution.resolved()).get().satisfies(location -> {
            assertThat(location.chunkId()).isEqualTo(42L);
            assertThat(location.location()).isEqualTo(new FindingLocationResolver.Location(6, 6));
            assertThat(location.locationRole()).isEqualTo("DATA_OUTPUT");
        });
    }

    @Test
    void relocatesCrossMethodSqlSinkToCompleteUnsafeLikeConstruction() {
        CodeChunk search = chunk(39, 45, """
                StringBuilder sql = new StringBuilder("SELECT * FROM staff WHERE 1 = 1");
                MapSqlParameterSource parameters = new MapSqlParameterSource();
                for (int index = 0; index < request.searchFields().size(); index++) {
                    appendCondition(sql, parameters, request.searchFields().get(index), index);
                }
                return jdbcTemplate.queryForList(sql.toString(), parameters);
                """);
        search.setId(100L);
        CodeChunk append = chunk(48, 71, """
                private void appendCondition(
                        StringBuilder sql,
                        MapSqlParameterSource parameters,
                        StaffSearchField searchField,
                        int index) {
                    if (searchField == null || !ALLOWED_FIELDS.contains(searchField.fieldName())) {
                        throw new IllegalArgumentException("Unsupported search field");
                    }

                    String parameterName = searchField.fieldName() + "_" + index;
                    if (EXACT_MATCH_FIELDS.contains(searchField.fieldName())) {
                        sql.append(" AND ")
                                .append(searchField.fieldName())
                                .append(" = :")
                                .append(parameterName);
                        parameters.addValue(parameterName, searchField.fieldValue());
                    } else {
                        sql.append(" AND ")
                                .append(searchField.fieldName())
                                .append(" LIKE '%")
                                .append(searchField.fieldValue())
                                .append("%'");
                    }
                }
                """);
        append.setId(101L);
        Map<Long, CodeChunk> chunks = Map.of(100L, search, 101L, append);
        List<LlmGateway.LocationCandidate> candidates = FindingLocationResolver.locationCandidates(
                VulnerabilityType.SQL_INJECTION, chunks, chunks.keySet());
        LlmGateway.LocationCandidate execution = candidates.stream()
                .filter(candidate -> candidate.purposes().contains("IMPACT"))
                .filter(candidate -> candidate.source().contains("queryForList"))
                .findFirst().orElseThrow();
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                VulnerabilityType.SQL_INJECTION, Severity.HIGH, Confidence.HIGH,
                "员工搜索 LIKE 条件存在 SQL 注入", "fieldValue 被直接拼入 LIKE 条件", "参数化 LIKE 值",
                100L, List.of(100L, 101L), 45, 45);
        LlmGateway.CriticDecision decision = confirmedDecision(
                execution, "UNSAFE_QUERY", "QUERY_EXECUTION");

        FindingLocationResolver.LocationResolution resolution = FindingLocationResolver.resolveCriticLocation(
                proposal, decision, chunks, chunks.keySet(), candidates);

        assertThat(resolution.resolved()).get().satisfies(location -> {
            assertThat(location.chunkId()).isEqualTo(101L);
            assertThat(location.location()).isEqualTo(new FindingLocationResolver.Location(65, 69));
            assertThat(location.locationKind()).isEqualTo("ROOT_CAUSE");
        });
    }

    @Test
    void usesProtectedDataOperationAsAuthorizationResponsibilityAnchorInsteadOfControllerEntry() {
        CodeChunk entry = new CodeChunk(UUID.randomUUID(), "CustomerController.java", "CustomerController#find",
                "/customers/{id}", 20, 20, "return customerService.find(id);",
                "JAVA_METHOD", "Long id", "@GetMapping", "customerService.find");
        entry.setId(201L);
        CodeChunk access = chunk(40, 40, "return customerRepository.findById(id).orElseThrow();");
        access.setId(202L);
        assertMissingControlAnchorsAt(VulnerabilityType.AUTHORIZATION, "MISSING_AUTHORIZATION_CHECK",
                entry, access, 202L);
    }

    @Test
    void usesSensitiveOperationAsValidationResponsibilityAnchorInsteadOfControllerEntry() {
        CodeChunk entry = new CodeChunk(UUID.randomUUID(), "PaymentController.java", "PaymentController#purchase",
                "/payments", 20, 20, "return paymentService.purchase(request);",
                "JAVA_METHOD", "PurchaseRequest request", "@PostMapping", "paymentService.purchase");
        entry.setId(301L);
        CodeChunk debit = chunk(55, 55,
                "accountRepository.debit(request.accountNo(), request.amount());");
        debit.setId(302L);
        assertMissingControlAnchorsAt(VulnerabilityType.VALIDATION_BYPASS, "MISSING_VALIDATION",
                entry, debit, 302L);
    }

    @Test
    void selectsSensitiveLogOutputAsRootCauseInsteadOfDelegatingEntry() {
        CodeChunk entry = new CodeChunk(UUID.randomUUID(), "OtpController.java", "OtpController#issue",
                "/otp", 10, 10, "return otpService.issue(request);",
                "JAVA_METHOD", "OtpRequest request", "@PostMapping", "otpService.issue");
        entry.setId(401L);
        CodeChunk output = chunk(60, 60, "LOGGER.info(\"issued otp={}\", otp);");
        output.setId(402L);
        assertRootCauseAt(VulnerabilityType.SENSITIVE_INFORMATION_DISCLOSURE,
                "UNSAFE_DATA_EXPOSURE", entry, output, 402L);
    }

    @Test
    void selectsUnsafeHtmlRenderAsStoredXssRootCauseInsteadOfPersistenceImpact() {
        CodeChunk storage = chunk(70, 70, "commentRepository.save(comment);");
        storage.setId(501L);
        CodeChunk render = new CodeChunk(UUID.randomUUID(), "comment-view.js", "renderComment", null,
                90, 90, "element.innerHTML = comment.body;", "TEXT_JS", "", "", "");
        render.setId(502L);
        assertRootCauseAt(VulnerabilityType.STORED_XSS, "UNSAFE_OUTPUT", storage, render, 502L);
    }

    private void assertMissingControlAnchorsAt(VulnerabilityType type, String rootCause,
                                               CodeChunk selected, CodeChunk expected, long expectedChunkId) {
        FindingLocationResolver.ResolvedPrimary location = resolveAcrossChunks(
                type, rootCause, selected, expected);
        assertThat(location.chunkId()).isEqualTo(expectedChunkId);
        assertThat(location.locationKind()).isEqualTo("RESPONSIBILITY_ANCHOR");
    }

    private void assertRootCauseAt(VulnerabilityType type, String rootCause,
                                   CodeChunk selected, CodeChunk expected, long expectedChunkId) {
        FindingLocationResolver.ResolvedPrimary location = resolveAcrossChunks(
                type, rootCause, selected, expected);
        assertThat(location.chunkId()).isEqualTo(expectedChunkId);
        assertThat(location.locationKind()).isEqualTo("ROOT_CAUSE");
    }

    private FindingLocationResolver.ResolvedPrimary resolveAcrossChunks(
            VulnerabilityType type, String rootCause, CodeChunk selected, CodeChunk expected) {
        Map<Long, CodeChunk> chunks = Map.of(selected.getId(), selected, expected.getId(), expected);
        List<LlmGateway.LocationCandidate> candidates = FindingLocationResolver.locationCandidates(
                type, chunks, chunks.keySet());
        LlmGateway.LocationCandidate selectedCandidate = candidates.stream()
                .filter(candidate -> candidate.chunkId() == selected.getId()).findFirst().orElseThrow();
        LlmGateway.FindingProposal proposal = new LlmGateway.FindingProposal(
                type, Severity.HIGH, Confidence.HIGH, "安全问题", "已验证的跨方法证据链", "服务端修复",
                selected.getId(), List.of(selected.getId(), expected.getId()),
                selectedCandidate.startLine(), selectedCandidate.endLine());
        LlmGateway.CriticDecision decision = confirmedDecision(
                selectedCandidate, rootCause, selectedCandidate.roles().stream().findFirst().orElse("DATA_ACCESS"));
        return FindingLocationResolver.resolveCriticLocation(
                proposal, decision, chunks, chunks.keySet(), candidates).resolved().orElseThrow();
    }

    private LlmGateway.CriticDecision confirmedDecision(
            LlmGateway.LocationCandidate candidate, String rootCause, String role) {
        return new LlmGateway.CriticDecision(true, Confidence.HIGH, "证据链确认",
                com.deepaudit.domain.FindingDeltaStatus.NEW, candidate.chunkId(),
                candidate.startLine(), candidate.endLine(), rootCause, role, candidate.candidateId(),
                LlmGateway.CriticVerdict.CONFIRMED, List.of());
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
