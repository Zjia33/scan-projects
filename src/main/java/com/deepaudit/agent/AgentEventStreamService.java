package com.deepaudit.agent;

import com.deepaudit.domain.AgentEvent;
import com.deepaudit.mapper.AgentEventMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class AgentEventStreamService {
    private static final long STREAM_TIMEOUT_MILLIS = 30L * 60L * 1_000L;

    private final AgentEventMapper eventMapper;
    private final ConcurrentHashMap<UUID, CopyOnWriteArrayList<SseEmitter>> subscribers =
            new ConcurrentHashMap<>();

    public AgentEventStreamService(AgentEventMapper eventMapper) {
        this.eventMapper = eventMapper;
    }

    // 注册任务级 SSE 订阅并先回放已持久化事件，避免连接前的日志缺失。
    public SseEmitter subscribe(UUID taskId) {
        SseEmitter emitter = new SseEmitter(STREAM_TIMEOUT_MILLIS);
        CopyOnWriteArrayList<SseEmitter> taskSubscribers =
                subscribers.computeIfAbsent(taskId, ignored -> new CopyOnWriteArrayList<>());
        taskSubscribers.add(emitter);
        Runnable cleanup = () -> remove(taskId, emitter);
        emitter.onCompletion(cleanup);
        emitter.onTimeout(() -> {
            cleanup.run();
            emitter.complete();
        });
        emitter.onError(ignored -> cleanup.run());
        try {
            emitter.send(SseEmitter.event().name("connected").data(taskId.toString()));
            List<AgentEvent> backlog = eventMapper.findByTaskId(taskId);
            for (AgentEvent event : backlog) send(emitter, event);
        } catch (Exception exception) {
            cleanup.run();
            emitter.completeWithError(exception);
        }
        return emitter;
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
                emitter.complete();
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
}
