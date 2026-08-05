package com.deepaudit.codegraph;

public class CodeGraphException extends RuntimeException {
    public CodeGraphException(String message) {
        super(message);
    }

    public CodeGraphException(String message, Throwable cause) {
        super(message, cause);
    }
}
