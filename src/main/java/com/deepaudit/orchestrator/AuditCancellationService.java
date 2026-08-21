package com.deepaudit.orchestrator;

import com.deepaudit.agent.AgentTraceService;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AuditStatus;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.mapper.AuditTaskMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** 统一管理审计任务的持久化取消状态和当前进程中的协作式线程中断。 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuditCancellationService {
    private static final String CANCELLED_STAGE = "审计已由用户中断";

    private final AuditTaskMapper taskMapper;
    private final AgentTraceService traceService;
    private final Set<UUID> cancelledTasks = ConcurrentHashMap.newKeySet();
    private final Set<UUID> finishedTasks = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<UUID, Set<Thread>> workers = new ConcurrentHashMap<>();

    public CancellationResult requestCancellation(UUID taskId) {
        AuditTask before = requireTask(taskId);
        if (before.getStatus().isTerminal()) {
            boolean cancelled = before.getStatus() == AuditStatus.CANCELLED;
            return new CancellationResult(before, false,
                    cancelled ? "审计任务已经中断" : "审计任务已经结束，无法再中断");
        }

        int updated = taskMapper.cancelIfActive(taskId, Instant.now(), CANCELLED_STAGE);
        AuditTask current = requireTask(taskId);
        if (current.getStatus() != AuditStatus.CANCELLED) {
            if (current.getStatus().isTerminal()) {
                return new CancellationResult(current, false, "审计任务已经结束，无法再中断");
            }
            throw new IllegalStateException("审计任务状态已发生变化，未能中断: " + taskId);
        }

        cancelledTasks.add(taskId);
        interruptWorkers(taskId);
        if (updated == 1) {
            publishCancellationEvent(taskId, before.getCurrentStage());
            log.info("审计任务中断请求已生效：taskId={}，previousStage={}，progress={}%",
                    taskId, before.getCurrentStage(), before.getProgress());
        }
        return new CancellationResult(current, updated == 1, "审计任务已中断");
    }

    public WorkerRegistration registerWorker(UUID taskId) {
        throwIfCancellationRequested(taskId);
        Thread thread = Thread.currentThread();
        workers.computeIfAbsent(taskId, ignored -> ConcurrentHashMap.newKeySet()).add(thread);
        if (cancelledTasks.contains(taskId)) {
            unregister(taskId, thread);
            thread.interrupt();
            throw new AuditCancelledException(taskId);
        }
        return () -> {
            unregister(taskId, thread);
            // 线程池线程会被复用，消费本次取消留下的中断标记，避免污染下一项任务。
            if (cancelledTasks.contains(taskId)) Thread.interrupted();
        };
    }

    public void throwIfCancellationRequested(UUID taskId) {
        if (cancelledTasks.contains(taskId)) {
            throw new AuditCancelledException(taskId);
        }
    }

    public boolean isCancellationRequested(UUID taskId) {
        if (cancelledTasks.contains(taskId)) return true;
        AuditTask task = taskMapper.findById(taskId);
        if (task != null && task.getStatus() == AuditStatus.CANCELLED) {
            cancelledTasks.add(taskId);
            return true;
        }
        return false;
    }

    public void taskFinished(UUID taskId) {
        finishedTasks.add(taskId);
        cleanupTokenIfIdle(taskId);
    }

    private void interruptWorkers(UUID taskId) {
        Set<Thread> taskWorkers = workers.get(taskId);
        if (taskWorkers == null) return;
        for (Thread worker : taskWorkers) worker.interrupt();
    }

    private void unregister(UUID taskId, Thread thread) {
        workers.computeIfPresent(taskId, (ignored, current) -> {
            current.remove(thread);
            return current.isEmpty() ? null : current;
        });
        cleanupTokenIfIdle(taskId);
    }

    private void cleanupTokenIfIdle(UUID taskId) {
        if (!finishedTasks.contains(taskId) || workers.containsKey(taskId)) return;
        cancelledTasks.remove(taskId);
        finishedTasks.remove(taskId);
    }

    private void publishCancellationEvent(UUID taskId, String previousStage) {
        try {
            traceService.event(taskId, null, AgentType.ORCHESTRATOR, AgentEventType.CANCELLED,
                    "用户中断了审计任务；中断前阶段：" + (previousStage == null ? "未知" : previousStage));
        } catch (RuntimeException exception) {
            log.warn("审计任务 {} 已中断，但取消事件记录失败", taskId, exception);
        }
    }

    private AuditTask requireTask(UUID taskId) {
        AuditTask task = taskMapper.findById(taskId);
        if (task == null) throw new java.util.NoSuchElementException("审计任务不存在: " + taskId);
        return task;
    }

    @FunctionalInterface
    public interface WorkerRegistration extends AutoCloseable {
        @Override
        void close();
    }

    public record CancellationResult(AuditTask task, boolean changed, String message) {
    }
}
