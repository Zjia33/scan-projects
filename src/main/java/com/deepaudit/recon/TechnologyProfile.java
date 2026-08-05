package com.deepaudit.recon;

import java.util.List;

/**
 * 由本地文件事实确定的项目技术栈，不依赖模型猜测。
 */
public record TechnologyProfile(List<String> frameworks,
                                List<String> securityFrameworks,
                                List<String> persistenceFrameworks,
                                List<String> buildTools,
                                List<String> securityAnnotations,
                                List<String> evidence) {

    // 校验并规范化 TechnologyProfile 的构造参数。
    public TechnologyProfile {
        frameworks = immutable(frameworks);
        securityFrameworks = immutable(securityFrameworks);
        persistenceFrameworks = immutable(persistenceFrameworks);
        buildTools = immutable(buildTools);
        securityAnnotations = immutable(securityAnnotations);
        evidence = immutable(evidence);
    }

    public static TechnologyProfile empty() {
        return new TechnologyProfile(List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    // 仅保留整体技术类别，去除文件级探测依据，供 Recon 及后续 Agent 作为紧凑项目背景。
    public TechnologyProfile withoutEvidence() {
        return new TechnologyProfile(frameworks, securityFrameworks, persistenceFrameworks,
                buildTools, securityAnnotations, List.of());
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
