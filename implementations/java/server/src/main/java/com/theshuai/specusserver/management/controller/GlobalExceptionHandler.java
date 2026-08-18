package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.service.RateLimitedException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

/**
 * 集中处理 management API 抛出的领域异常。原本散落在 {@code AdminController} 中。
 *
 * <p>映射规则：
 * <ul>
 *   <li>{@link IllegalArgumentException} → 400，参数/约束类错误</li>
 *   <li>{@link IllegalStateException} → 409，状态冲突（例如客户端离线时手动下发映射）</li>
 *   <li>{@link RateLimitedException} → 429，触发限流或房间配额</li>
 *   <li>{@link DataIntegrityViolationException} → 400，DB 唯一/外键约束</li>
 * </ul>
 */
@RestControllerAdvice(basePackages = "com.theshuai.specusserver.management.controller")
public class GlobalExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, String>> handleResponseStatus(ResponseStatusException exception) {
        String message = StringUtils.hasText(exception.getReason()) ? exception.getReason() : "请求失败";
        return ResponseEntity.status(exception.getStatusCode()).body(Map.of("error", message));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException exception) {
        return ResponseEntity.badRequest().body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(RateLimitedException.class)
    public ResponseEntity<Map<String, String>> handleRateLimited(RateLimitedException exception) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS);
        if (exception.getRetryAfterSeconds() > 0) {
            response.header("Retry-After", Long.toString(exception.getRetryAfterSeconds()));
        }
        return response.body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, String>> handleIllegalState(IllegalStateException exception) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, String>> handleDataIntegrityViolation(DataIntegrityViolationException exception) {
        return ResponseEntity.badRequest().body(Map.of("error", "客户端名称已存在或数据不符合约束"));
    }
}
