package com.deepaudit.agent;

import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

@Slf4j
@Service
public class ProfessionalAgentRunner {
    private final AgentRuntime agentRuntime;
    private final Executor executor;

    public ProfessionalAgentRunner(AgentRuntime agentRuntime,
                                   @Qualifier("professionalAgentExecutor") Executor executor) {
        this.agentRuntime = agentRuntime;
        this.executor = executor;
    }

    // 在受控线程池中并行执行专业调查，并汇总候选与格式失败数。
    public BatchResult investigate(UUID taskId, List<AgentTask> plan,
                                   LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        // 每个规划任务独立运行，单个格式错误不会取消其他专业调查。
        List<CompletableFuture<TaskResult>> futures = plan.stream()
                .map(task -> CompletableFuture.supplyAsync(
                        () -> investigateOne(taskId, task, recon, chunks), executor))
                .toList();

        List<AgentCandidate> candidates = new ArrayList<>();
        int formatFailures = 0;
        for (CompletableFuture<TaskResult> future : futures) {
            TaskResult result = join(future);
            result.candidate().ifPresent(candidates::add);
            if (result.formatFailure()) formatFailures++;
        }
        return new BatchResult(List.copyOf(candidates), formatFailures);
    }

    // 将不可解析的模型响应降级为当前调查失败，其余运行异常继续上抛。
    private TaskResult investigateOne(UUID taskId, AgentTask task,
                                      LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        try {
            return new TaskResult(agentRuntime.investigate(taskId, task, recon, chunks), false);
        } catch (AiResponseFormatException exception) {
            log.warn("任务 {} 的 {} 在目标 {} 上返回不可解析 JSON，跳过该调查任务并继续扫描",
                    taskId, task.agentType(), task.chunkId());
            return new TaskResult(Optional.empty(), true);
        }
    }

    // 解包异步异常并保留原始运行时异常语义。
    private TaskResult join(CompletableFuture<TaskResult> future) {
        try {
            return future.join();
        } catch (CompletionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof RuntimeException runtimeException) throw runtimeException;
            throw new IllegalStateException("专业 Agent 并行调查失败", cause);
        }
    }

    private record TaskResult(Optional<AgentCandidate> candidate, boolean formatFailure) {
    }

    public record BatchResult(List<AgentCandidate> candidates, int formatFailures) {
    }
}
