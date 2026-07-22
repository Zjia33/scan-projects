package com.deepaudit.semantic;

import com.deepaudit.domain.CodeChunk;
import com.deepaudit.mapper.SecurityFlowMapper;
import com.deepaudit.mapper.SemanticCallEdgeMapper;
import com.deepaudit.mapper.SemanticSymbolMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

@Service
public class SemanticAnalysisService {
    private static final Logger log = LoggerFactory.getLogger(SemanticAnalysisService.class);

    private final SemanticAnalysisProperties properties;
    private final LightweightSemanticAnalyzer analyzer;
    private final SemanticSymbolMapper symbolMapper;
    private final SemanticCallEdgeMapper edgeMapper;
    private final SecurityFlowMapper flowMapper;
    private final TransactionTemplate transactionTemplate;

    public SemanticAnalysisService(SemanticAnalysisProperties properties, LightweightSemanticAnalyzer analyzer,
                                   SemanticSymbolMapper symbolMapper, SemanticCallEdgeMapper edgeMapper,
                                   SecurityFlowMapper flowMapper, PlatformTransactionManager transactionManager) {
        this.properties = properties;
        this.analyzer = analyzer;
        this.symbolMapper = symbolMapper;
        this.edgeMapper = edgeMapper;
        this.flowMapper = flowMapper;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    // 重建符号、调用边和安全数据流，并在单个事务中替换旧语义索引。
    public Summary rebuild(UUID taskId, Path root, List<CodeChunk> chunks) {
        if (!properties.isEnabled()) {
            // 功能关闭时仍清理历史结果，避免后续读取到过期语义证据。
            transactionTemplate.executeWithoutResult(status -> deleteExisting(taskId));
            return new Summary(0, 0, 0, 0, 0, 0, 0, 0);
        }
        try {
            // taskId 用于标记结果归属，root 用于读取源码，chunks 用于把语义节点关联回可引用证据。
            // 先在事务外完成耗时的源码解析和路径搜索，避免分析期间长期占用数据库事务。
            LightweightSemanticAnalyzer.Result result = analyzer.analyze(taskId, root, chunks);
            // 只有完整分析成功后才进入事务替换旧索引，防止半成品符号图被后续 Agent 读取。
            transactionTemplate.executeWithoutResult(status -> {
                deleteExisting(taskId);
                batches(result.symbols(), 300, symbolMapper::insertBatch);
                batches(result.edges(), 500, edgeMapper::insertBatch);
                batches(result.flows(), 300, flowMapper::insertBatch);
            });
            LightweightSemanticAnalyzer.CallGraphCoverage coverage = result.coverage();
            log.info("任务 {} 轻量语义分析完成：{} 个符号、{} 条调用边、{} 条安全数据流；"
                            + "调用点={}，精确={}，启发式={}，框架={}，外部={}，未解析={}，内部解析率={}％",
                    taskId, result.symbols().size(), result.edges().size(), result.flows().size(),
                    coverage.totalCallSites(), coverage.exactResolvedCallSites(),
                    coverage.heuristicResolvedCallSites(), coverage.frameworkResolvedCallSites(),
                    coverage.externalCallSites(), coverage.unresolvedCallSites(),
                    String.format(java.util.Locale.ROOT, "%.1f", coverage.internalResolutionRate() * 100));
            return new Summary(result.symbols().size(), result.edges().size(), result.flows().size(),
                    coverage.totalCallSites(), coverage.exactResolvedCallSites(),
                    coverage.heuristicResolvedCallSites(), coverage.frameworkResolvedCallSites(),
                    coverage.unresolvedCallSites());
        } catch (Exception exception) {
            throw new IllegalStateException("轻量级跨过程语义分析失败: " + exception.getMessage(), exception);
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
    private interface BatchInserter<T> { int insert(List<T> values); }

    public record Summary(int symbolCount, int callEdgeCount, int securityFlowCount,
                          int totalCallSites, int exactResolvedCallSites,
                          int heuristicResolvedCallSites, int frameworkResolvedCallSites,
                          int unresolvedCallSites) {}
}
