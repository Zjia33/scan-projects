package com.deepaudit.domain;

// 定义 FindingDeltaStatus 使用的固定状态或类型。
public enum FindingDeltaStatus {
    NEW,
    PERSISTING;

    // 增量扫描只区分本次变更新增和 Base/Target 持续存在。
    public static FindingDeltaStatus normalize(FindingDeltaStatus value) {
        return value == PERSISTING ? PERSISTING : NEW;
    }
}
