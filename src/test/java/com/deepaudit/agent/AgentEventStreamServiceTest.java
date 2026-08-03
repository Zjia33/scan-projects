package com.deepaudit.agent;

import com.deepaudit.mapper.AgentEventMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

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

        SseEmitter subscribed = service.subscribe(UUID.randomUUID());

        assertThat(subscribed).isSameAs(emitter);
        verify(emitter).complete();
        verify(emitter, never()).completeWithError(any());
        verifyNoInteractions(eventMapper);
    }

    @Test
    void stillPropagatesServerSideBacklogFailureThroughEmitter() throws Exception {
        AgentEventStreamService service = spy(new AgentEventStreamService(eventMapper));
        doReturn(emitter).when(service).createEmitter();
        IllegalStateException failure = new IllegalStateException("database unavailable");
        doThrow(failure).when(eventMapper).findByTaskId(any());

        service.subscribe(UUID.randomUUID());

        verify(emitter).completeWithError(failure);
        verify(emitter, never()).complete();
    }
}
