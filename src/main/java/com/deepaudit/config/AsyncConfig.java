package com.deepaudit.config;

import com.deepaudit.ai.AiProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
public class AsyncConfig {

    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        // 第一版优先缩短单项目审计时间：项目之间排队，项目内部由专业 Agent 线程池并行。
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(20);
        executor.setThreadNamePrefix("audit-worker-");
        executor.initialize();
        return executor;
    }

    @Bean(name = "professionalAgentExecutor")
    public Executor professionalAgentExecutor(AiProperties properties) {
        int parallelism = Math.max(1, Math.min(properties.getProfessionalAgentParallelism(), 16));
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(parallelism);
        executor.setMaxPoolSize(parallelism);
        executor.setQueueCapacity(Math.max(200, properties.getMaxAuditTargets()));
        executor.setThreadNamePrefix("professional-agent-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        return executor;
    }
}
