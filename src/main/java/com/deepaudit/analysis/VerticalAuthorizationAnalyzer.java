package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Order(30)
@Component
public class VerticalAuthorizationAnalyzer implements VulnerabilityAnalyzer {

    @Override
    public VulnerabilityType type() { return VulnerabilityType.AUTHORIZATION; }

    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            if (chunk.getEndpoint() == null) continue;
            boolean sensitive = AnalyzerSupport.containsAny(chunk.getEndpoint() + " " + chunk.getSymbolName(),
                    "admin", "permission", "role", "refund", "withdraw", "export", "delete", "disable", "approve");
            boolean guarded = AnalyzerSupport.containsAny(chunk.getContent(),
                    "@preauthorize", "@secured", "@rolesallowed", "checkpermission", "hasrole", "hasauthority", "checkrole");
            if (sensitive && !guarded) {
                int line = chunk.getStartLine();
                results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                        "敏感接口未发现角色或权限限制", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                        "该接口名称或功能具有管理、审批、退款、导出等敏感特征，但未在方法附近发现权限保护。",
                        AnalyzerSupport.evidence(chunk, line),
                        "在路由和方法层同时配置明确权限，并在关键 Service 操作前进行服务端授权检查。"));
            }
        }
        return results;
    }
}
