package com.deepaudit.analysis;

import com.deepaudit.domain.CodeChunk;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

public record AnalysisContext(UUID taskId, Path projectRoot, List<CodeChunk> chunks) {
}
