package com.deepaudit.agent;

import com.deepaudit.domain.VulnerabilityType;

import java.util.List;

/**
 * 增量扫描的纯事实审查载体。它描述实际变更、影响关系和可核验代码，不预判漏洞类型。
 */
public record IncrementalReviewUnit(String unitId, long primaryChunkId, String filePath,
                                    String symbolName, String endpoint, String chunkType,
                                    String changeType, String analysisScope,
                                    List<VulnerabilityType> allowedTypes,
                                    List<VulnerabilityType> mandatoryTypes,
                                    List<String> facts, String parameters, String annotations,
                                    String calledSymbols, String baseCodeExcerpt,
                                    String targetCodeExcerpt, String changeSummary,
                                    String relatedContext, String deterministicEvidence) {

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
        relatedContext = safe(relatedContext);
        deterministicEvidence = safe(deterministicEvidence);
    }

    // 补充一次受控的调用关系和相关代码正文，供 NEED_CONTEXT 后复判。
    public IncrementalReviewUnit withRelatedContext(String context) {
        return new IncrementalReviewUnit(unitId, primaryChunkId, filePath, symbolName, endpoint,
                chunkType, changeType, analysisScope, allowedTypes, mandatoryTypes, facts,
                parameters, annotations, calledSymbols, baseCodeExcerpt, targetCodeExcerpt,
                changeSummary, context, deterministicEvidence);
    }

    private static <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
