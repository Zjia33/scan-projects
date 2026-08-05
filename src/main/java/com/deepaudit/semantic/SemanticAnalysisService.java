package com.deepaudit.semantic;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticSymbolMapper;
import com.deepaudit.util.ExecutionTiming;
import com.deepaudit.util.TimingDetailLog;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
public class SemanticAnalysisService {
    private final SemanticAnalysisProperties properties;
    private final LightweightSemanticAnalyzer localSemanticAnalyzer;
    private final SemanticSymbolMapper symbolMapper;
    private final SemanticCallEdgeMapper edgeMapper;
    private final SecurityFlowMapper flowMapper;
    private final TransactionTemplate transactionTemplate;

    public SemanticAnalysisService(SemanticAnalysisProperties properties, LightweightSemanticAnalyzer localSemanticAnalyzer,
                                   SemanticSymbolMapper symbolMapper, SemanticCallEdgeMapper edgeMapper,
                                   SecurityFlowMapper flowMapper, PlatformTransactionManager transactionManager) {
        this.properties = properties;
        this.localSemanticAnalyzer = localSemanticAnalyzer;
        this.symbolMapper = symbolMapper;
        this.edgeMapper = edgeMapper;
        this.flowMapper = flowMapper;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    // 仅重建 CHANGED 作用域内的局部语义补充和安全流索引。
    public Summary rebuild(UUID taskId, Path root, List<CodeChunk> chunks, Set<Long> scopeChunkIds) {
        long rebuildStarted = ExecutionTiming.start();
        if (!properties.isEnabled()) {
            // 功能关闭时仍清理历史结果，避免后续读取到过期语义证据。
            transactionTemplate.executeWithoutResult(status -> deleteExisting(taskId));
            TimingDetailLog.info("执行耗时：taskId={}，stage=SCOPED_SEMANTIC_ANALYSIS，elapsedMs={}，status=DISABLED",
                    taskId, ExecutionTiming.elapsedMillis(rebuildStarted));
            return new Summary(0, 0, 0, 0, 0);
        }
        try {
            // taskId 用于标记结果归属，root 用于读取源码，chunks 用于把语义节点关联回可引用证据。
            // 先在事务外完成耗时的源码解析和路径搜索，避免分析期间长期占用数据库事务。
            long parseStarted = ExecutionTiming.start();
            LightweightSemanticAnalyzer.Result result = localSemanticAnalyzer.enrich(
                    taskId, root, chunks, scopeChunkIds);
            long parseElapsedMs = ExecutionTiming.elapsedMillis(parseStarted);
            // 只有完整分析成功后才进入事务替换旧索引，防止半成品符号图被后续 Agent 读取。
            long persistStarted = ExecutionTiming.start();
            transactionTemplate.executeWithoutResult(status -> {
                deleteExisting(taskId);
                batches(result.symbols(), 300, symbolMapper::insertBatch);
                batches(result.edges(), 500, edgeMapper::insertBatch);
                batches(result.flows(), 300, flowMapper::insertBatch);
            });
            long persistElapsedMs = ExecutionTiming.elapsedMillis(persistStarted);
            LightweightSemanticAnalyzer.CallGraphCoverage coverage = result.coverage();
            TimingDetailLog.info("任务 {} CHANGED 局部语义索引完成：{} 个符号、{} 条边、{} 条安全数据流；"
                            + "框架语义边={}，局部调用点={}",
                    taskId, result.symbols().size(), result.edges().size(), result.flows().size(),
                    coverage.frameworkEdges(), coverage.localCallSites());
            TimingDetailLog.info("执行耗时：taskId={}，stage=CHANGED_LOCAL_SEMANTIC_ANALYSIS，elapsedMs={}，parseElapsedMs={}，persistElapsedMs={}，scopeChunks={}，symbols={}，edges={}，flows={}",
                    taskId, ExecutionTiming.elapsedMillis(rebuildStarted), parseElapsedMs, persistElapsedMs,
                    scopeChunkIds == null ? 0 : scopeChunkIds.size(),
                    result.symbols().size(), result.edges().size(), result.flows().size());
            return new Summary(result.symbols().size(), result.edges().size(), result.flows().size(),
                    coverage.frameworkEdges(), coverage.localCallSites());
        } catch (Exception exception) {
            log.error("执行耗时：taskId={}，stage=SCOPED_SEMANTIC_ANALYSIS，elapsedMs={}，status=FAILED，error={}",
                    taskId, ExecutionTiming.elapsedMillis(rebuildStarted), exception.getClass().getSimpleName());
            throw new IllegalStateException("CHANGED 局部语义分析失败: " + exception.getMessage(), exception);
        }
    }

    // 按外键依赖顺序删除安全流、调用边和符号。
    private void deleteExisting(UUID taskId) {
        flowMapper.deleteByTaskId(taskId);
        edgeMapper.deleteByTaskId(taskId);
        symbolMapper.deleteByTaskId(taskId);
    }

    // 将大型语义结果拆批写入，控制单条 SQL 的参数规模。
    private <T> void batches(List<T> values, int size, BatchInserter<T> inserter) {
        for (int start = 0; start < values.size(); start += size) {
            inserter.insert(values.subList(start, Math.min(start + size, values.size())));
        }
    }

    @FunctionalInterface
    private interface BatchInserter<T> {
        // 将一批分析结果写入对应存储。
        int insert(List<T> values);
    }

    public record Summary(int symbolCount, int callEdgeCount, int securityFlowCount,
                          int frameworkEdgeCount, int localCallSiteCount) {}
}
