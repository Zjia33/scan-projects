package com.deepaudit;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@MapperScan("com.deepaudit.mapper")
@SpringBootApplication
public class DeepAuditApplication {

    public static void main(String[] args) {
        SpringApplication.run(DeepAuditApplication.class, args);
    }
}
