package com.deepaudit.web;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ApiExceptionHandlerTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new FailureController())
                .setControllerAdvice(new ApiExceptionHandler())
                .build();
    }

    @Test
    void doesNotWriteJsonBodyIntoEventStreamResponse() throws Exception {
        mockMvc.perform(get("/stream-failure").accept(MediaType.TEXT_EVENT_STREAM))
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(""));
    }

    @Test
    void keepsJsonErrorBodyForOrdinaryApiResponse() throws Exception {
        mockMvc.perform(get("/json-failure").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.message").value("server failure"));
    }

    @Test
    void doesNotAttemptAnotherWriteAfterResponseWasCommitted() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.flushBuffer();

        assertThat(new ApiExceptionHandler().serverError(
                new IOException("connection aborted"), response)).isNull();
    }

    @RestController
    private static class FailureController {

        @GetMapping(value = "/stream-failure", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
        void streamFailure(HttpServletResponse response) throws IOException {
            response.setContentType(MediaType.TEXT_EVENT_STREAM_VALUE);
            throw new IOException("connection aborted");
        }

        @GetMapping(value = "/json-failure", produces = MediaType.APPLICATION_JSON_VALUE)
        void jsonFailure() {
            throw new IllegalStateException("server failure");
        }
    }
}
