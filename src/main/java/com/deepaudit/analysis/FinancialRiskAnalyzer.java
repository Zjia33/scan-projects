package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Order(70)
@Component
public class FinancialRiskAnalyzer implements VulnerabilityAnalyzer {

    @Override
    public VulnerabilityType type() { return VulnerabilityType.FINANCIAL_RISK; }

    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            String content = chunk.getContent();
            if (!AnalyzerSupport.containsAny(content, "amount", "price", "balance", "payment", "refund", "coupon", "withdraw")) {
                continue;
            }
            if (AnalyzerSupport.matches(content, "(?:double|float)\\s+\\w*(?:amount|price|balance|money)")) {
                int line = AnalyzerSupport.matchingLine(chunk, "(?:double|float)\\s+\\w*(?:amount|price|balance|money)");
                results.add(finding(context, chunk, line, "金额使用浮点类型",
                        "金额字段使用 double/float，可能产生精度差异并在累计、退款或对账时造成损失。",
                        "使用 BigDecimal，并明确精度、舍入规则和数据库 decimal 类型。"));
            }
            boolean callback = AnalyzerSupport.containsAny(chunk.getEndpoint() == null ? "" : chunk.getEndpoint(), "callback", "notify", "webhook");
            boolean signature = AnalyzerSupport.containsAny(content, "verifysign", "checksignature", "validsignature", "hmac");
            if (callback && !signature) {
                int line = chunk.getStartLine();
                results.add(finding(context, chunk, line, "支付回调未发现验签",
                        "支付或通知回调中未发现签名校验，伪造请求可能修改订单或余额。",
                        "先验签，再核对商户号、订单号、金额和状态；成功处理必须具备幂等约束。"));
            }
            boolean changesMoney = AnalyzerSupport.containsAny(content, "setamount(", "setprice(", "setbalance(", "refund(", "withdraw(");
            boolean validates = AnalyzerSupport.containsAny(content, "compareto(", "signum(", "maxamount", "minamount", "idempot", "for update");
            if (changesMoney && !validates) {
                int line = AnalyzerSupport.matchingLine(chunk, "setAmount|setPrice|setBalance|refund|withdraw");
                results.add(finding(context, chunk, line, "资金操作缺少边界或幂等校验",
                        "金额、退款、提现或余额修改附近未发现正数范围、上限或幂等性检查。",
                        "使用服务端可信金额，校验范围和订单状态，并以唯一业务键实现数据库级幂等。"));
            }
        }
        return results;
    }

    private FindingDraft finding(AnalysisContext context, CodeChunk chunk, int line,
                                 String title, String description, String remediation) {
        return new FindingDraft(type(), Severity.HIGH, Confidence.LOW, title,
                chunk.getFilePath(), line, line, chunk.getEndpoint(), description,
                AnalyzerSupport.evidence(chunk, line),
                remediation);
    }
}
