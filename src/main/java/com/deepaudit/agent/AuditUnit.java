package com.deepaudit.agent;

import com.deepaudit.domain.VulnerabilityType;

import java.util.List;

// 聚合入口、调用事实和安全线索，作为轻量编排使用的紧凑审计单元。
public record AuditUnit(String unitId, long primaryChunkId, String filePath, String symbolName,
                        String endpoint, String unitType, String changeType, String analysisScope,
                        List<VulnerabilityType> candidateTypes, List<String> reasonCodes,
                        String parameters, String annotations, String callSummary,
                        String contextSummary, String codeOutline) {
    // 校验并规范化 AuditUnit 的构造参数。
    public AuditUnit {
        candidateTypes = candidateTypes == null ? List.of() : List.copyOf(candidateTypes);
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        parameters = safe(parameters);
        annotations = safe(annotations);
        callSummary = safe(callSummary);
        contextSummary = safe(contextSummary);
        codeOutline = safe(codeOutline);
    }

    // 用按需检索到的调用链和安全流替换上下文，供第二次轻量分流使用。
    public AuditUnit withContext(String expandedContext) {
        return new AuditUnit(unitId, primaryChunkId, filePath, symbolName, endpoint, unitType,
                changeType, analysisScope, candidateTypes, reasonCodes, parameters, annotations,
                callSummary, expandedContext, codeOutline);
    }

    // 执行 AuditUnit 中的 safe 处理。
    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
