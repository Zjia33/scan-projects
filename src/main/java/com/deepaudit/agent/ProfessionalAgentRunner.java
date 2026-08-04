package com.deepaudit.agent;

import com.deepaudit.ai.AiResponseFormatException;
import com.deepaudit.ai.LlmGateway;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.orchestrator.AuditCancellationService;
import com.deepaudit.orchestrator.AuditCancelledException;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
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

// 封装 ProfessionalAgentRunner 相关的数据与处理逻辑。
@Slf4j
@Service
public class ProfessionalAgentRunner {
    private final AgentRuntime agentRuntime;
    private final Executor executor;
    private final AuditCancellationService cancellationService;

    // 创建 ProfessionalAgentRunner 实例并初始化所需依赖或状态。
    public ProfessionalAgentRunner(AgentRuntime agentRuntime,
                                   @Qualifier("professionalAgentExecutor") Executor executor,
                                   AuditCancellationService cancellationService) {
        this.agentRuntime = agentRuntime;
        this.executor = executor;
        this.cancellationService = cancellationService;
    }

    // 在受控线程池中并行执行专业调查，并汇总候选与格式失败数。
    public BatchResult investigate(UUID taskId, List<AgentTask> plan,
                                   LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        long batchStarted = ExecutionTiming.start();
        TimingDetailLog.info("执行阶段开始：taskId={}，stage=PROFESSIONAL_AGENT_BATCH，tasks={}", taskId, plan.size());
        cancellationService.throwIfCancellationRequested(taskId);
        // 每个规划任务独立运行，单个格式错误不会取消其他专业调查。
        List<CompletableFuture<TaskResult>> futures = new ArrayList<>();
        List<AgentCandidate> candidates = new ArrayList<>();
        int formatFailures = 0;
        try {
            for (AgentTask task : plan) {
                cancellationService.throwIfCancellationRequested(taskId);
                futures.add(CompletableFuture.supplyAsync(
                        () -> investigateOne(taskId, task, recon, chunks), executor));
            }
            for (CompletableFuture<TaskResult> future : futures) {
                cancellationService.throwIfCancellationRequested(taskId);
                TaskResult result = join(future);
                result.candidate().ifPresent(candidates::add);
                if (result.formatFailure()) formatFailures++;
            }
        } catch (RuntimeException exception) {
            futures.forEach(future -> future.cancel(true));
            throw exception;
        }
        BatchResult batchResult = new BatchResult(List.copyOf(candidates), formatFailures);
        log.info("阶段耗时：taskId={}，阶段=专业安全Agent调查，耗时={}ms，说明=并行验证增量漏洞假设与证据，任务数={}，候选数={}，格式失败={}",
                taskId, ExecutionTiming.elapsedMillis(batchStarted), plan.size(),
                batchResult.candidates().size(), batchResult.formatFailures());
        return batchResult;
    }

    // 将不可解析的模型响应降级为当前调查失败，其余运行异常继续上抛。
    private TaskResult investigateOne(UUID taskId, AgentTask task,
                                      LlmGateway.ReconInsight recon, List<CodeChunk> chunks) {
        long taskStarted = ExecutionTiming.start();
        try (AuditCancellationService.WorkerRegistration ignored =
                     cancellationService.registerWorker(taskId)) {
            cancellationService.throwIfCancellationRequested(taskId);
            TaskResult result = new TaskResult(agentRuntime.investigate(taskId, task, recon, chunks), false);
            cancellationService.throwIfCancellationRequested(taskId);
            TimingDetailLog.info("执行耗时：taskId={}，stage=PROFESSIONAL_AGENT_TASK，agentType={}，chunkId={}，vulnerabilityType={}，elapsedMs={}，candidate={}",
                    taskId, task.agentType(), task.chunkId(), task.vulnerabilityType(),
                    ExecutionTiming.elapsedMillis(taskStarted), result.candidate().isPresent());
            return result;
        } catch (AuditCancelledException exception) {
            throw exception;
        } catch (AiResponseFormatException exception) {
            log.warn("任务 {} 的 {} 在目标 {} 上返回不可解析 JSON，跳过该调查任务并继续扫描；elapsedMs={}",
                    taskId, task.agentType(), task.chunkId(), ExecutionTiming.elapsedMillis(taskStarted));
            return new TaskResult(Optional.empty(), true);
        } catch (RuntimeException exception) {
            log.error("执行耗时：taskId={}，stage=PROFESSIONAL_AGENT_TASK，agentType={}，chunkId={}，vulnerabilityType={}，elapsedMs={}，status=FAILED，error={}",
                    taskId, task.agentType(), task.chunkId(), task.vulnerabilityType(),
                    ExecutionTiming.elapsedMillis(taskStarted), exception.getClass().getSimpleName());
            throw exception;
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

    // 封装 TaskResult 使用的不可变结构化数据。
    private record TaskResult(Optional<AgentCandidate> candidate, boolean formatFailure) {
    }

    // 封装 BatchResult 使用的不可变结构化数据。
    public record BatchResult(List<AgentCandidate> candidates, int formatFailures) {
    }
}
