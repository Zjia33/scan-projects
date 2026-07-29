package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;
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
