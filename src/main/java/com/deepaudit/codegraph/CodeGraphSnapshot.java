package com.deepaudit.codegraph;

// 区分同一增量任务中的基线和目标 CodeGraph 索引。
public enum CodeGraphSnapshot {
    BASE("base"),
    TARGET("target");

    private final String workspaceSuffix;

    CodeGraphSnapshot(String workspaceSuffix) {
        this.workspaceSuffix = workspaceSuffix;
    }

    public String workspaceSuffix() {
        return workspaceSuffix;
    }
}
