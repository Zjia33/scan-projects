package com.deepaudit.web;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

import jakarta.servlet.http.HttpServletResponse;

import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;

// 封装 ApiExceptionHandler 相关的数据与处理逻辑。
@RestControllerAdvice
public class ApiExceptionHandler {

    // 处理 badRequest 对应的异常并生成 API 响应。
    @ExceptionHandler({IllegalArgumentException.class})
    public ResponseEntity<?> badRequest(Exception exception, HttpServletResponse servletResponse) {
        return response(HttpStatus.BAD_REQUEST, exception.getMessage(), servletResponse);
    }

    // 处理 notFound 对应的异常并生成 API 响应。
    @ExceptionHandler({NoSuchElementException.class, EmptyResultDataAccessException.class})
    public ResponseEntity<?> notFound(Exception exception, HttpServletResponse servletResponse) {
        return response(HttpStatus.NOT_FOUND, "请求的项目或任务不存在", servletResponse);
    }

    // 处理 asyncRequestTimeout 对应的异常并生成 API 响应。
    @ExceptionHandler(AsyncRequestTimeoutException.class)
    public ResponseEntity<Void> asyncRequestTimeout() {
        return ResponseEntity.noContent().build();
    }

    // 处理 serverError 对应的异常并生成 API 响应。
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> serverError(Exception exception, HttpServletResponse servletResponse) {
        return response(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage(), servletResponse);
    }

    // 执行 ApiExceptionHandler 中的 response 处理。
    private ResponseEntity<?> response(HttpStatus status, String message,
                                       HttpServletResponse servletResponse) {
        if (servletResponse.isCommitted()) return null;
        String contentType = servletResponse.getContentType();
        if (contentType != null && contentType.toLowerCase(java.util.Locale.ROOT)
                .startsWith(MediaType.TEXT_EVENT_STREAM_VALUE)) {
            return ResponseEntity.status(status).build();
        }
        return ResponseEntity.status(status).body(Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "message", message == null ? status.getReasonPhrase() : message
        ));
    }
}
