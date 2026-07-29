package com.deepaudit.ai;

// 表示 AiUnavailableException 对应的异常情况。
public class AiUnavailableException extends RuntimeException {
    // 创建 AiUnavailableException 实例并初始化所需依赖或状态。
    public AiUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    // 创建 AiUnavailableException 实例并初始化所需依赖或状态。
    public AiUnavailableException(String message) {
        super(message);
    }
}
