package com.deepaudit.config;

import com.deepaudit.ai.AiProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

// 配置 AsyncConfig 所需的应用组件。
@Configuration
public class AsyncConfig {

    // 创建并注册 auditExecutor 对应的 Spring Bean。
    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        // 项目之间串行排队，项目内部的模型阶段使用各自的受控线程池。
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(20);
        executor.setThreadNamePrefix("audit-worker-");
        executor.initialize();
        return executor;
    }

    // 创建并注册 professionalAgentExecutor 对应的 Spring Bean。
    @Bean(name = "professionalAgentExecutor")
    public Executor professionalAgentExecutor(AiProperties properties) {
        int parallelism = Math.max(1, Math.min(properties.getProfessionalAgentParallelism(), 16));
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(parallelism);
        executor.setMaxPoolSize(parallelism);
        executor.setQueueCapacity(Math.max(200, properties.getProfessionalAgentQueueCapacity()));
        executor.setThreadNamePrefix("professional-agent-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        return executor;
    }

    @Bean(name = "triageAgentExecutor")
    public Executor triageAgentExecutor(AiProperties properties) {
        return modelExecutor("triage-agent-", properties.getTriageParallelism(), 200);
    }

    private Executor modelExecutor(String threadPrefix, int requestedParallelism, int queueCapacity) {
        int parallelism = Math.max(1, Math.min(requestedParallelism, 16));
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(parallelism);
        executor.setMaxPoolSize(parallelism);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix(threadPrefix);
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        return executor;
    }
}
