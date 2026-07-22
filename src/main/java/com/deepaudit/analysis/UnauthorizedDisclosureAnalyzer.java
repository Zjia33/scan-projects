package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Order(40)
@Component
public class UnauthorizedDisclosureAnalyzer implements VulnerabilityAnalyzer {

    @Override
    public VulnerabilityType type() { return VulnerabilityType.UNAUTHORIZED_DISCLOSURE; }

    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            if (chunk.getEndpoint() == null) continue;
            boolean publicAccess = AnalyzerSupport.containsAny(chunk.getContent(),
                    "permitall", "@anonymous", "@permitall")
                    || AnalyzerSupport.containsAny(chunk.getEndpoint(), "/public/", "/open/", "/anonymous/");
            boolean sensitive = AnalyzerSupport.containsAny(chunk.getContent(),
                    "password", "secret", "apikey", "privatekey", "idcard", "bankcard", "balance", "token", "salary");
            if (publicAccess && sensitive) {
                int line = AnalyzerSupport.matchingLine(chunk,
                        "password|secret|apiKey|privateKey|idCard|bankCard|balance|token|salary");
                results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                        "公开接口可能返回敏感信息", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                        "无需授权访问的接口附近出现密码、令牌、身份、银行卡或余额等敏感字段。",
                        AnalyzerSupport.evidence(chunk, line),
                        "要求登录和数据权限校验；使用专用响应 DTO，并通过字段白名单控制返回数据。"));
            }
        }
        return results;
    }
}
