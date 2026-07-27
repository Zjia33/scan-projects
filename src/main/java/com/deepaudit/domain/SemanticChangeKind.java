package com.deepaudit.domain;

// 表示 Base 与 Target 方法快照之间可解释的语义变化类型。
public enum SemanticChangeKind {
    METHOD_ADDED,
    METHOD_MODIFIED,
    METHOD_DELETED,
    SIGNATURE_CHANGED,
    GUARD_ADDED,
    GUARD_REMOVED
}
