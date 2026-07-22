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

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
