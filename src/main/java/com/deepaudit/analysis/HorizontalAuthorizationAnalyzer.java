package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.Severity;
import com.deepaudit.domain.VulnerabilityType;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

// 负责 HorizontalAuthorizationAnalyzer 对应的确定性分析与事实提取。
@Order(20)
@Component
public class HorizontalAuthorizationAnalyzer implements VulnerabilityAnalyzer {

    // 执行 HorizontalAuthorizationAnalyzer 中的 type 处理。
    @Override
    public VulnerabilityType type() { return VulnerabilityType.AUTHORIZATION; }

    // 分析并提取 analyze 对应的事实。
    @Override
    public List<FindingDraft> analyze(AnalysisContext context) {
        List<FindingDraft> results = new ArrayList<>();
        for (CodeChunk chunk : context.chunks()) {
            if (chunk.getEndpoint() == null) continue;
            boolean resourceId = AnalyzerSupport.containsAny(chunk.getEndpoint() + chunk.getContent(),
                    "{id}", "orderid", "userid", "accountid", "resourceid");
            boolean directLookup = AnalyzerSupport.containsAny(chunk.getContent(),
                    "getbyid(", "selectbyid(", "findbyid(", "deletebyid(", "updatebyid(");
            boolean ownership = AnalyzerSupport.containsAny(chunk.getContent(),
                    "currentuserid", "loginuserid", "ownerid", "tenantid", "createdby", "datascope", "checkowner");
            if (resourceId && directLookup && !ownership) {
                int line = AnalyzerSupport.matchingLine(chunk, "(?:get|select|find|delete|update)ById\\s*\\(");
                results.add(new FindingDraft(type(), Severity.HIGH, Confidence.MEDIUM,
                        "按资源 ID 直接操作但未发现归属校验", chunk.getFilePath(), line, line, chunk.getEndpoint(),
                        "接口接收资源标识并直接查询或修改记录，当前方法中未发现用户、租户或数据范围校验。",
                        AnalyzerSupport.evidence(chunk, line),
                        "查询条件中同时约束当前用户或租户，并在 Service 层验证资源归属；不要只依赖前端隐藏。"));
            }
        }
        return results;
    }
}
