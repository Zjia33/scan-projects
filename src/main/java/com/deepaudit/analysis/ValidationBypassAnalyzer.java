package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Order(60)
@Component
public class ValidationBypassAnalyzer implements VulnerabilityAnalyzer {

    private static final String BYPASS_PATTERN = "skipverify|bypassverify|ignoreverification|verify\\w*\\s*\\([^;]+;\\s*(?!if)|catch\\s*\\([^)]*\\)\\s*\\{[^}]{0,300}(?:warn|ignore|continue)";

    @Override
    public VulnerabilityType type() { return VulnerabilityType.VALIDATION_BYPASS; }

    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            boolean verificationFlow = AnalyzerSupport.containsAny(chunk.getContent(),
                    "verify", "captcha", "otp", "signature", "checkpassword", "approve", "validatestatus");
            if (!verificationFlow || !AnalyzerSupport.matches(chunk.getContent(), BYPASS_PATTERN)) continue;
            int line = AnalyzerSupport.matchingLine(chunk, BYPASS_PATTERN);
            results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                    "验证流程可能被跳过或失败后继续执行", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                    "验证标志可能由客户端控制、验证结果可能未使用，或验证异常被捕获后业务继续执行。",
                    AnalyzerSupport.evidence(chunk, line),
                    "所有验证采用失败即终止；禁止客户端控制跳过标志；统一封装校验并覆盖同一业务的所有入口。"));
        }
        return results;
    }
}
