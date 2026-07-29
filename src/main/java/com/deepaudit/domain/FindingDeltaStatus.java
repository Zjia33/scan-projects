package com.deepaudit.domain;

// 定义 FindingDeltaStatus 使用的固定状态或类型。
public enum FindingDeltaStatus {
    BASELINE,
    NEW,
    // 仅用于兼容历史数据；当前增量结果统一归一化为 NEW。
    REGRESSED,
    PERSISTING,
    // 仅用于兼容历史数据；当前增量结果统一归一化为 NEW。
    AFFECTED;

    // 全量扫描只展示基线；增量扫描只区分本次变更新增和 Base/Target 持续存在。
    public static FindingDeltaStatus normalizeFor(ScanMode scanMode, FindingDeltaStatus value) {
        if (scanMode != ScanMode.INCREMENTAL) return BASELINE;
        return value == PERSISTING ? PERSISTING : NEW;
    }
}
