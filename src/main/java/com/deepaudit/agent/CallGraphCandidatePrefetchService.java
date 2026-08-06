package com.deepaudit.agent;

import com.deepaudit.codegraph.CodeGraphIntegrationService;
import com.deepaudit.codegraph.CodeGraphProperties;
import com.deepaudit.domain.CodeChunk;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 在专业 Agent 首轮推理前只预取直接调用关系的符号和位置，不读取或分块候选源码。
 */
@Service
@RequiredArgsConstructor
public class CallGraphCandidatePrefetchService {
    private final CodeGraphIntegrationService codeGraphIntegrationService;
    private final CodeGraphProperties properties;

    public AgentTask enrich(AgentTask task, List<CodeChunk> chunks) {
        if (task == null || chunks == null || chunks.isEmpty()) return task;
        CodeChunk anchor = chunks.stream()
                .filter(chunk -> chunk.getId() != null && chunk.getId() == task.chunkId())
                .findFirst().orElse(null);
        if (anchor == null || anchor.getChunkType() == null
                || !anchor.getChunkType().startsWith("JAVA_METHOD")) return task;

        long started = ExecutionTiming.start();
        int limit = Math.max(1, properties.getAgentContextLimit());
        List<CodeGraphIntegrationService.ImpactCandidate> candidates = new ArrayList<>();
        boolean incomplete = false;
        for (CodeGraphIntegrationService.Direction direction : List.of(
                CodeGraphIntegrationService.Direction.CALLERS,
                CodeGraphIntegrationService.Direction.CALLEES)) {
            CodeGraphIntegrationService.CandidatePage page = codeGraphIntegrationService.relatedCandidates(
                    anchor.getTaskId(), anchor, direction, limit);
            if (page.error() != null) {
                incomplete = true;
                continue;
            }
            candidates.addAll(page.candidates());
            incomplete |= page.truncated();
        }
        TimingDetailLog.info("任务 {} 调用关系符号预取完成：chunkId={}，candidates={}，incomplete={}，elapsedMs={}",
                anchor.getTaskId(), anchor.getId(), candidates.size(), incomplete,
                ExecutionTiming.elapsedMillis(started));
        if (candidates.isEmpty()) return task;

        StringBuilder hint = new StringBuilder("调用关系符号候选（仅含位置元数据，尚未读取源码；读取后由服务端自动确认 CodeGraph 来源和 Target 映射）：");
        for (CodeGraphIntegrationService.ImpactCandidate candidate : candidates) {
            var location = candidate.location();
            hint.append("\n- candidateId=").append(candidate.candidateId())
                    .append(" | direction=").append(candidate.direction())
                    .append(" | symbol=").append(location.name())
                    .append(" | kind=").append(location.kind())
                    .append(" | file=").append(location.filePath())
                    .append(':').append(location.startLine());
        }
        if (incomplete) {
            hint.append("\n候选列表可能未覆盖全部关系；需要更多候选时应缩小方向或目标后重新查询。");
        }
        hint.append("\n需要源码时，使用 read_verified_relations 选择需要的 candidateId；即使只读取一个候选，candidateIds 也以单元素数组传入；无需额外调用关系验证工具。");
        return task.withAdditionalRuleHint(hint.toString());
    }
}
