package com.deepaudit.semantic;

import com.deepaudit.domain.SemanticCallEdge;

import java.util.Set;

/** 限定轻量语义层可以持久化的框架/安全关系；普通 Java 调用统一由 CodeGraph 发现。 */
public final class FrameworkSemanticEdgePolicy {
    private static final Set<String> SUPPORTED_TYPES = Set.of(
            "MYBATIS_MAPPER_API",
            "PERSISTENCE_API",
            "DATABASE_API",
            "SECURITY_GUARD",
            "SPRING_EVENT",
            "MYBATIS_XML",
            "PERSISTENCE_FIELD"
    );

    private FrameworkSemanticEdgePolicy() {
    }

    public static boolean supports(SemanticCallEdge edge) {
        return edge != null && edge.getEdgeType() != null
                && SUPPORTED_TYPES.contains(edge.getEdgeType());
    }
}
