package com.deepaudit;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@MapperScan("com.deepaudit.mapper")
@SpringBootApplication
public class DeepAuditApplication {

    // 启动 DeepAudit Spring Boot 应用。
    public static void main(String[] args) {
        SpringApplication.run(DeepAuditApplication.class, args);
    }
}
