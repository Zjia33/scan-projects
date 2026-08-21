package com.deepaudit.recon;

/** Recon 模型可读取的构建或应用配置文件；文件来自不可变 Target 快照。 */
public record ReconFrameworkFile(String path, String kind, String content) {
}
