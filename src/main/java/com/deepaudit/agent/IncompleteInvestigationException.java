package com.deepaudit.agent;

/** 表示单个专业调查因工具、覆盖或预算限制未能得到完整结论。 */
public class IncompleteInvestigationException extends RuntimeException {
    public IncompleteInvestigationException(String message) {
        super(message);
    }
}
