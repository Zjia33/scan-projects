package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Order(50)
@Component
public class StoredXssAnalyzer implements VulnerabilityAnalyzer {

    private static final String UNSAFE_SINK = "v-html|dangerouslySetInnerHTML|th:utext|innerHTML\\s*=|<%=|\\|\\s*safe";
    private static final String JAVA_HTML_LITERAL = "<(?:html|body|article|div|span|h[1-6])\\b";

    @Override
    public VulnerabilityType type() { return VulnerabilityType.STORED_XSS; }

    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            if (AnalyzerSupport.matches(chunk.getContent(), UNSAFE_SINK)) {
                int line = AnalyzerSupport.matchingLine(chunk, UNSAFE_SINK);
                results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                        "持久化内容可能被非转义渲染", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                        "模板或前端代码使用了原始 HTML 渲染能力；如果数据来自评论、公告等持久化字段，可能形成存储型 XSS。",
                        AnalyzerSupport.evidence(chunk, line),
                        "保存时使用可靠 HTML 白名单清洗，输出时按上下文编码；不需要富文本时移除原始 HTML 渲染。"));
            } else if (javaHtmlOutputWithoutEncoding(chunk)) {
                int line = AnalyzerSupport.matchingLine(chunk, JAVA_HTML_LITERAL);
                results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                        "持久化文本可能未经编码进入 HTML 响应", chunk.getFilePath(), line, line,
                        chunk.getEndpoint(),
                        "Java 代码把持久化读取结果拼接为 HTML，当前变化范围内未发现可靠的上下文编码或白名单清洗；"
                                + "需要继续核对共享存储对象的写入入口。",
                        AnalyzerSupport.evidence(chunk, line),
                        "对普通文本执行上下文相关的 HTML 编码；需要富文本时在写入端使用可靠白名单清洗。"));
            } else if (AnalyzerSupport.containsAny(chunk.getContent(), ".save(", "insert(", "updatebyid(")
                    && AnalyzerSupport.containsAny(chunk.getContent(), "content", "comment", "description", "notice", "nickname")
                    && !AnalyzerSupport.containsAny(chunk.getContent(), "sanitize", "encodeforhtml", "htmlclean", "jsoup.clean")) {
                int line = AnalyzerSupport.matchingLine(chunk, "\\.(?:save|insert|updateById)\\s*\\(");
                results.add(new FindingDraft(type(), Severity.MEDIUM, Confidence.LOW,
                        "可控文本持久化前未发现 HTML 清洗", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                        "发现评论、描述或公告类字段写入持久层，但当前上下文中未发现清洗；需要结合展示端人工确认。",
                        AnalyzerSupport.evidence(chunk, line),
                        "追踪该字段的全部展示位置；对富文本使用白名单清洗，对普通文本保持默认转义。"));
            }
        }
        return results;
    }

    private boolean javaHtmlOutputWithoutEncoding(CodeChunk chunk) {
        String content = chunk.getContent();
        return AnalyzerSupport.matches(content, JAVA_HTML_LITERAL)
                && AnalyzerSupport.containsAny(content, ".findall(", ".findby", ".query(",
                ".select(", ".title()", ".content()", ".comment()", ".description()")
                && !AnalyzerSupport.containsAny(content, "htmlutils.htmlescape", "encodeforhtml",
                "sanitize", "htmlclean", "jsoup.clean");
    }
}
