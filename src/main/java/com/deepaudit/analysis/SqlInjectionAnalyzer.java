package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Order(10)
@Component
public class SqlInjectionAnalyzer implements VulnerabilityAnalyzer {

    private static final String DYNAMIC_SQL = "\\$\\{|(?:select|update|delete|insert)\\s+[^\\n;]*(?:\\+|concat\\s*\\()|create(?:native)?query\\s*\\([^\\n;]*\\+|statement\\s*\\.\\s*execute";

    @Override
    public VulnerabilityType type() { return VulnerabilityType.SQL_INJECTION; }

    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            // 代码块规则匹配
            if (!AnalyzerSupport.matches(chunk.getContent(), DYNAMIC_SQL)) {
                continue;
            }
            int line = AnalyzerSupport.matchingLine(chunk, DYNAMIC_SQL);
            results.add(new FindingDraft(type(), Severity.CRITICAL, Confidence.HIGH,
                    "动态 SQL 可能引入 SQL 注入", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                    "外部输入可能通过字符串拼接、MyBatis 动态替换或 Statement 进入 SQL 结构。",
                    AnalyzerSupport.evidence(chunk, line),
                    "使用预编译参数；MyBatis 使用 #{}；动态表名、列名和排序方向必须使用固定白名单。"));
        }
        return results;
    }
}
