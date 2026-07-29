package com.deepaudit.ai;

/**
 * 模型接口可用，但响应在本地修复和模型重建后仍无法解析。
 */
public class AiResponseFormatException extends AiUnavailableException {
    // 创建 AiResponseFormatException 实例并初始化所需依赖或状态。
    public AiResponseFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
