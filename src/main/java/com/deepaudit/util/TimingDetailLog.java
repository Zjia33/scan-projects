package com.deepaudit.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Routes high-cardinality timing diagnostics to the dedicated timing file.
 */
public final class TimingDetailLog {
    private static final Logger LOGGER = LoggerFactory.getLogger("com.deepaudit.timing.detail");

    private TimingDetailLog() {
    }

    public static void info(String message, Object... arguments) {
        LOGGER.info(message, arguments);
    }

    public static void warn(String message, Object... arguments) {
        LOGGER.warn(message, arguments);
    }
}
