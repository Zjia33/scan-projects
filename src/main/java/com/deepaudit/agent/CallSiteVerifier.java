package com.deepaudit.agent;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.Confidence;
import com.deepaudit.domain.SemanticCallEdge;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.expr.MethodCallExpr;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/** Deterministically promotes a graph candidate only when the current source contains its call site. */
public final class CallSiteVerifier {
    private CallSiteVerifier() {
    }

    public static Verification verify(CodeChunk caller, CodeChunk callee, List<CodeChunk> chunks,
                                      List<SemanticCallEdge> semanticEdges) {
        if (caller == null || callee == null || caller.getId() == null || callee.getId() == null) {
            return Verification.unverified("调用双方没有可引用的代码块 ID");
        }
        SemanticCallEdge persisted = semanticEdges == null ? null : semanticEdges.stream()
                .filter(edge -> caller.getId().equals(edge.getCallerChunkId()))
                .filter(edge -> callee.getId().equals(edge.getCalleeChunkId()))
                .filter(CallSiteVerifier::isVerifiedSemanticEdge)
                .sorted(Comparator.comparingInt(CallSiteVerifier::evidenceRank).reversed())
                .findFirst().orElse(null);
        if (persisted != null) {
            return new Verification(true, Math.max(1, persisted.getCallSiteLine()),
                    safe(persisted.getExpression()), "SEMANTIC_EDGE",
                    persisted.getResolutionReason());
        }

        if (!"JAVA_METHOD".equals(caller.getChunkType())
                || !"JAVA_METHOD".equals(callee.getChunkType())) {
            return Verification.unverified("调用双方不是可执行本地调用点验证的 Java 方法块");
        }
        String method = methodName(callee.getSymbolName());
        if (method.isBlank()) return Verification.unverified("被调用方法没有可解析的方法名");
        List<CodeChunk> sameNameTargets = chunks.stream()
                .filter(chunk -> "JAVA_METHOD".equals(chunk.getChunkType()))
                .filter(chunk -> method.equals(methodName(chunk.getSymbolName())))
                .filter(chunk -> chunk.getId() != null)
                .toList();
        if (sameNameTargets.size() != 1 || !callee.getId().equals(sameNameTargets.get(0).getId())) {
            return Verification.unverified("本地存在同名或重载目标，无法唯一绑定 CodeGraph 候选");
        }

        String source = caller.getContent() == null ? "" : caller.getContent().strip();
        if (source.isBlank()) return Verification.unverified("调用方代码块没有可验证源码");
        try {
            List<MethodCallExpr> calls = StaticJavaParser.parse("class __DeepAuditCallSite__ {\n"
                            + source + "\n}")
                    .findAll(MethodCallExpr.class).stream()
                    .filter(call -> method.equals(call.getNameAsString().toLowerCase(Locale.ROOT)))
                    .toList();
            if (calls.size() != 1) {
                return Verification.unverified(calls.isEmpty()
                        ? "调用方源码中没有找到目标调用表达式"
                        : "调用方源码中存在多个同名调用点，无法唯一定位");
            }
            MethodCallExpr call = calls.get(0);
            int relativeLine = call.getBegin().map(position -> position.line - 2).orElse(0);
            int absoluteLine = Math.max(1, caller.getStartLine() + Math.max(0, relativeLine));
            return new Verification(true, absoluteLine, safe(call.toString()),
                    "LOCAL_AST_UNIQUE_CALL", "当前快照源码中唯一定位到目标方法调用点");
        } catch (RuntimeException exception) {
            return Verification.unverified("调用方源码无法完成 Java AST 调用点验证");
        }
    }

    private static boolean isVerifiedSemanticEdge(SemanticCallEdge edge) {
        if (edge.getConfidence() == null || edge.getConfidence() == Confidence.LOW) return false;
        return !"CODEGRAPH_CALL".equals(edge.getEdgeType()) || edge.getConfidence() == Confidence.HIGH;
    }

    private static int evidenceRank(SemanticCallEdge edge) {
        if (edge.getConfidence() == Confidence.HIGH) return 2;
        return 1;
    }

    private static String methodName(String symbol) {
        if (symbol == null) return "";
        String value = symbol.strip();
        int parameters = value.indexOf('(');
        if (parameters >= 0) value = value.substring(0, parameters);
        int separator = Math.max(value.lastIndexOf('#'), Math.max(value.lastIndexOf('.'), value.lastIndexOf(':')));
        return (separator >= 0 ? value.substring(separator + 1) : value).toLowerCase(Locale.ROOT);
    }

    private static String safe(String value) {
        if (value == null) return "";
        String result = value.replaceAll("\\s+", " ").strip();
        return result.substring(0, Math.min(result.length(), 300));
    }

    public record Verification(boolean verified, int callSiteLine, String expression,
                               String type, String reason) {
        public Verification {
            expression = expression == null ? "" : expression;
            type = type == null ? "UNVERIFIED" : type;
            reason = reason == null ? "" : reason;
        }

        public static Verification unverified(String reason) {
            return new Verification(false, 0, "", "UNVERIFIED", reason);
        }
    }
}
