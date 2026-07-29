package com.deepaudit.domain;

// 定义 AgentEventType 使用的固定状态或类型。
public enum AgentEventType {
    STARTED, MODEL_CALL, REASONING, PLAN, TOOL_CALL, OBSERVATION, HYPOTHESIS, FINDING, REJECTED, COMPLETED, ERROR
}
