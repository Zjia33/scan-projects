package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

// 封装 AnalysisContext 使用的不可变结构化数据。
public record AnalysisContext(UUID taskId, Path projectRoot, List<CodeChunk> chunks) {
}
