package com.deepaudit.agent;

import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.AgentType;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.domain.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProfessionalAgentRunnerTest {

    @Test
    void professionalAgentsRunConcurrentlyWithinOneProject() throws Exception {
        AgentRuntime runtime = mock(AgentRuntime.class);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ProfessionalAgentRunner runner = new ProfessionalAgentRunner(runtime, executor);
        CountDownLatch twoAgentsStarted = new CountDownLatch(2);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximumActive = new AtomicInteger();
        when(runtime.investigate(any(), any(), any(), anyList())).thenAnswer(invocation -> {
            int current = active.incrementAndGet();
            maximumActive.accumulateAndGet(current, Math::max);
            twoAgentsStarted.countDown();
            try {
                if (!twoAgentsStarted.await(2, TimeUnit.SECONDS)) {
                    throw new AssertionError("专业 Agent 没有并行启动");
                }
                Thread.sleep(40);
                return Optional.empty();
            } finally {
                active.decrementAndGet();
            }
        });
        List<AgentTask> plan = List.of(
                task(1, AgentType.SQL_INJECTION, VulnerabilityType.SQL_INJECTION),
                task(2, AgentType.AUTHORIZATION, VulnerabilityType.AUTHORIZATION),
                task(3, AgentType.STORED_XSS, VulnerabilityType.STORED_XSS),
                task(4, AgentType.FINANCIAL_RISK, VulnerabilityType.FINANCIAL_RISK));

        try {
            ProfessionalAgentRunner.BatchResult result = runner.investigate(
                    UUID.randomUUID(), plan, mock(LlmGateway.ReconInsight.class), List.<CodeChunk>of());

            assertThat(result.candidates()).isEmpty();
            assertThat(result.formatFailures()).isZero();
            assertThat(maximumActive).hasValueGreaterThan(1);
            verify(runtime, times(4)).investigate(any(), any(), any(), anyList());
        } finally {
            executor.shutdownNow();
        }
    }

    private AgentTask task(long chunkId, AgentType agentType, VulnerabilityType type) {
        return new AgentTask(chunkId, agentType, type, "测试并行调查", "规则提示");
    }
}
