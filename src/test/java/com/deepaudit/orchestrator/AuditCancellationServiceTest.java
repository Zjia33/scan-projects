package com.deepaudit.orchestrator;

import com.deepaudit.agent.AgentTraceService;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.AuditStatus;
import com.deepaudit.domain.AuditTask;
import com.deepaudit.mapper.AuditTaskMapper;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuditCancellationServiceTest {

    @Test
    void persistsCancellationAndInterruptsRegisteredWorker() throws Exception {
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditTask task = task(taskId, AuditStatus.ANALYSIS);
        AtomicReference<AuditTask> stored = new AtomicReference<>(task);
        when(taskMapper.findById(taskId)).thenAnswer(ignored -> stored.get());
        when(taskMapper.cancelIfActive(eq(taskId), any(), any())).thenAnswer(ignored -> {
            AuditTask current = stored.get();
            current.moveTo(AuditStatus.CANCELLED, current.getProgress(), "审计已由用户中断");
            current.setVersion(current.getVersion() + 1);
            return 1;
        });
        AuditCancellationService service = new AuditCancellationService(taskMapper, traceService);
        CountDownLatch registered = new CountDownLatch(1);
        CountDownLatch stopped = new CountDownLatch(1);

        Thread worker = new Thread(() -> {
            try (AuditCancellationService.WorkerRegistration ignored = service.registerWorker(taskId)) {
                registered.countDown();
                try {
                    new CountDownLatch(1).await();
                } catch (InterruptedException exception) {
                    service.throwIfCancellationRequested(taskId);
                }
            } catch (AuditCancelledException exception) {
                stopped.countDown();
            }
        }, "audit-cancellation-test-worker");
        worker.start();
        assertThat(registered.await(2, TimeUnit.SECONDS)).isTrue();

        AuditCancellationService.CancellationResult result = service.requestCancellation(taskId);

        assertThat(stopped.await(2, TimeUnit.SECONDS)).isTrue();
        worker.join(2_000);
        assertThat(result.changed()).isTrue();
        assertThat(result.task().getStatus()).isEqualTo(AuditStatus.CANCELLED);
        verify(traceService).event(eq(taskId), eq(null), eq(AgentType.ORCHESTRATOR),
                eq(AgentEventType.CANCELLED), any());
    }

    @Test
    void completedTaskIsAnIdempotentNoOp() {
        UUID taskId = UUID.randomUUID();
        AuditTaskMapper taskMapper = mock(AuditTaskMapper.class);
        AgentTraceService traceService = mock(AgentTraceService.class);
        AuditTask task = task(taskId, AuditStatus.COMPLETED);
        when(taskMapper.findById(taskId)).thenReturn(task);
        AuditCancellationService service = new AuditCancellationService(taskMapper, traceService);

        AuditCancellationService.CancellationResult result = service.requestCancellation(taskId);

        assertThat(result.changed()).isFalse();
        assertThat(result.task().getStatus()).isEqualTo(AuditStatus.COMPLETED);
        verify(taskMapper, never()).cancelIfActive(any(), any(), any());
    }

    private AuditTask task(UUID taskId, AuditStatus status) {
        AuditTask task = new AuditTask(UUID.randomUUID(), "a".repeat(40), "b".repeat(40), "a".repeat(40));
        task.setId(taskId);
        task.moveTo(status, 74, status == AuditStatus.COMPLETED ? "扫描完成" : "专业 Agent 调查中");
        return task;
    }
}
