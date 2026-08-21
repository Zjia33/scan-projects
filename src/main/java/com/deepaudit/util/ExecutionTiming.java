package com.deepaudit.util;

import java.util.concurrent.TimeUnit;

/**
 * Uses the monotonic clock for execution-duration measurements.
 * 使用单调时钟进行执行持续时间测量。
 */
public final class ExecutionTiming {
    private ExecutionTiming() {
    }

    public static long start() {
        return System.nanoTime();
    }

    public static long elapsedMillis(long startedNanos) {
        return Math.max(0L, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos));
    }
}
