package com.deepaudit.agent;

import com.deepaudit.domain.VulnerabilityType;

import java.util.List;

/**
 * 增量扫描的 CHANGED 纯事实审查载体。Triage 只据此定位可疑变更，不预载入跨方法源码。
 */
public record IncrementalReviewUnit(String unitId, long primaryChunkId, String filePath,
                                    String symbolName, String endpoint, String chunkType,
                                    String changeType,
                                    List<VulnerabilityType> allowedTypes,
                                    List<VulnerabilityType> mandatoryTypes,
                                    List<String> facts, String parameters, String annotations,
                                    String calledSymbols, String baseCodeExcerpt,
                                    String targetCodeExcerpt, String changeSummary,
                                    String deterministicEvidence, int startLine, int endLine) {

    public IncrementalReviewUnit {
        allowedTypes = immutable(allowedTypes);
        mandatoryTypes = immutable(mandatoryTypes);
        facts = immutable(facts);
        parameters = safe(parameters);
        annotations = safe(annotations);
        calledSymbols = safe(calledSymbols);
        baseCodeExcerpt = safe(baseCodeExcerpt);
        targetCodeExcerpt = safe(targetCodeExcerpt);
        changeSummary = safe(changeSummary);
        deterministicEvidence = safe(deterministicEvidence);
    }

    private static <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
