package com.deepaudit.codegraph;

// 表示 CodeGraphException 对应的异常情况。
public class CodeGraphException extends RuntimeException {
    // 创建 CodeGraphException 实例并初始化所需依赖或状态。
    public CodeGraphException(String message) {
        super(message);
    }

    // 创建 CodeGraphException 实例并初始化所需依赖或状态。
    public CodeGraphException(String message, Throwable cause) {
        super(message, cause);
    }
}
