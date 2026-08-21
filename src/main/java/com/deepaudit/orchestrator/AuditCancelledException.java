package com.deepaudit.orchestrator;

import java.util.UUID;

/** 表示审计任务收到用户中断请求，调用方应停止后续分析且不能将任务标记为失败。 */
public class AuditCancelledException extends RuntimeException {
    public AuditCancelledException(UUID taskId) {
        super("审计任务已中断: " + taskId);
    }
}
