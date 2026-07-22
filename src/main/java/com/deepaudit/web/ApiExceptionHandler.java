package com.deepaudit.web;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler({IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> badRequest(Exception exception) {
        return response(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler({NoSuchElementException.class, EmptyResultDataAccessException.class})
    public ResponseEntity<Map<String, Object>> notFound(Exception exception) {
        return response(HttpStatus.NOT_FOUND, "请求的项目或任务不存在");
    }

    @ExceptionHandler(AsyncRequestTimeoutException.class)
    public ResponseEntity<Void> asyncRequestTimeout() {
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> serverError(Exception exception) {
        return response(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
    }

    private ResponseEntity<Map<String, Object>> response(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "message", message == null ? status.getReasonPhrase() : message
        ));
    }
}
