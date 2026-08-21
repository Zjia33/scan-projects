package com.deepaudit.agent;

import com.deepaudit.domain.AgentEvent;
import com.deepaudit.domain.AgentEventType;
import com.deepaudit.domain.AgentType;
import com.deepaudit.mapper.AgentEventMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentEventStreamServiceTest {

    @Mock
    private AgentEventMapper eventMapper;

    @Mock
    private SseEmitter emitter;

    @Test
    void treatsInitialWriteFailureAsClientDisconnect() throws Exception {
        AgentEventStreamService service = spy(new AgentEventStreamService(eventMapper));
        doReturn(emitter).when(service).createEmitter();
        doThrow(new IOException("connection aborted")).when(emitter)
                .send(any(SseEmitter.SseEventBuilder.class));
        doThrow(new IllegalStateException("async context already failed")).when(emitter).complete();

        SseEmitter subscribed = service.subscribe(UUID.randomUUID());

        assertThat(subscribed).isSameAs(emitter);
        verify(emitter).complete();
        verify(emitter, never()).completeWithError(any());
        verifyNoInteractions(eventMapper);
    }

    @Test
    void reportsServerSideBacklogFailureWithoutLeakingAsyncLifecycleError() throws Exception {
        AgentEventStreamService service = spy(new AgentEventStreamService(eventMapper));
        doReturn(emitter).when(service).createEmitter();
        IllegalStateException failure = new IllegalStateException("database unavailable");
        doThrow(failure).when(eventMapper).findByTaskId(any());
        doThrow(new IllegalStateException("async context already failed"))
                .when(emitter).completeWithError(failure);

        service.subscribe(UUID.randomUUID());

        verify(emitter).completeWithError(failure);
        verify(emitter, never()).complete();
    }

    @Test
    void clientDisconnectDuringPublishNeverFailsAuditThread() throws Exception {
        AgentEventStreamService service = spy(new AgentEventStreamService(eventMapper));
        doReturn(emitter).when(service).createEmitter();
        UUID taskId = UUID.randomUUID();
        when(eventMapper.findByTaskId(taskId)).thenReturn(List.of());
        doNothing().doThrow(new IllegalStateException("async context already failed"))
                .when(emitter).send(any(SseEmitter.SseEventBuilder.class));
        service.subscribe(taskId);

        AgentEvent event = new AgentEvent(taskId, null, AgentType.RECON,
                AgentEventType.OBSERVATION, "Recon 完成");

        assertThatNoException().isThrownBy(() -> service.publish(event));
        verify(emitter, never()).complete();
    }
}
