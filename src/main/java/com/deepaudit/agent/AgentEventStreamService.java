package com.deepaudit.agent;

import com.deepaudit.domain.AgentEvent;
import com.deepaudit.mapper.AgentEventMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
@RequiredArgsConstructor
public class AgentEventStreamService {
    private static final long STREAM_TIMEOUT_MILLIS = 30L * 60L * 1_000L;

    private final AgentEventMapper eventMapper;
    private final ConcurrentHashMap<UUID, CopyOnWriteArrayList<SseEmitter>> subscribers =
            new ConcurrentHashMap<>();

    // 注册任务级 SSE 订阅并先回放已持久化事件，避免连接前的日志缺失。
    public SseEmitter subscribe(UUID taskId) {
        SseEmitter emitter = createEmitter();
        CopyOnWriteArrayList<SseEmitter> taskSubscribers =
                subscribers.computeIfAbsent(taskId, ignored -> new CopyOnWriteArrayList<>());
        taskSubscribers.add(emitter);
        Runnable cleanup = () -> remove(taskId, emitter);
        emitter.onCompletion(cleanup);
        emitter.onTimeout(() -> {
            cleanup.run();
            safeComplete(emitter);
        });
        emitter.onError(ignored -> cleanup.run());
        try {
            emitter.send(SseEmitter.event().name("connected").data(taskId.toString()));
        } catch (Exception exception) {
            // 浏览器刷新、切换任务或网络断开都可能中止首次写入；按 SSE 生命周期结束处理，
            // 不再通过 completeWithError 分派给返回 JSON 的全局异常处理器。
            cleanup.run();
            safeComplete(emitter);
            return emitter;
        }
        List<AgentEvent> backlog;
        try {
            backlog = eventMapper.findByTaskId(taskId);
        } catch (RuntimeException exception) {
            cleanup.run();
            safeCompleteWithError(emitter, exception);
            return emitter;
        }
        for (AgentEvent event : backlog) {
            try {
                send(emitter, event);
            } catch (Exception exception) {
                cleanup.run();
                safeComplete(emitter);
                break;
            }
        }
        return emitter;
    }

    // 独立创建 emitter，便于验证首次写入失败时的连接关闭语义。
    SseEmitter createEmitter() {
        return new SseEmitter(STREAM_TIMEOUT_MILLIS);
    }

    // 将新事件广播给同一任务的所有在线订阅者并清理失效连接。
    public void publish(AgentEvent event) {
        List<SseEmitter> taskSubscribers = subscribers.get(event.getTaskId());
        if (taskSubscribers == null) return;
        for (SseEmitter emitter : taskSubscribers) {
            try {
                send(emitter, event);
            } catch (Exception exception) {
                remove(event.getTaskId(), emitter);
                // send 失败时 Servlet 容器可能已经完成 AsyncContext 并执行 onError。
                // 此处只注销订阅，不能再次 complete/dispatch，更不能让连接异常影响审计线程。
            }
        }
    }

    // 使用数据库事件 ID 作为 SSE ID，便于客户端稳定识别事件。
    private void send(SseEmitter emitter, AgentEvent event) throws IOException {
        SseEmitter.SseEventBuilder builder = SseEmitter.event().name("agent-event").data(event);
        if (event.getId() != null) builder.id(String.valueOf(event.getId()));
        emitter.send(builder);
    }

    // 移除结束连接，并在任务没有订阅者时释放映射项。
    private void remove(UUID taskId, SseEmitter emitter) {
        subscribers.computeIfPresent(taskId, (ignored, current) -> {
            current.remove(emitter);
            return current.isEmpty() ? null : current;
        });
    }

    private void safeComplete(SseEmitter emitter) {
        try {
            emitter.complete();
        } catch (RuntimeException ignored) {
            // AsyncContext 可能已由 Tomcat 在断连或超时路径中完成。
        }
    }

    private void safeCompleteWithError(SseEmitter emitter, Exception exception) {
        try {
            emitter.completeWithError(exception);
        } catch (RuntimeException ignored) {
            // 容器已处理异步错误时，不再尝试二次 dispatch。
        }
    }
}
