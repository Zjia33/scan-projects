package com.deepaudit.domain;

// 定义 HypothesisStatus 使用的固定状态或类型。
public enum HypothesisStatus {
    NEW, INVESTIGATING, SUPPORTED, CHALLENGED, CONFIRMED, CONFIRMED_UNLOCATED,
    REJECTED, INSUFFICIENT_EVIDENCE
}
