package com.deepaudit.mapper;

import com.deepaudit.domain.SemanticSymbol;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

// 定义 SemanticSymbolMapper 的数据库访问操作。
public interface SemanticSymbolMapper {
    // 删除数据库中 deleteByTaskId 对应的记录。
    int deleteByTaskId(@Param("taskId") UUID taskId);
    // 向数据库写入 insertBatch 对应的记录。
    int insertBatch(@Param("symbols") List<SemanticSymbol> symbols);
    // 从数据库查询 findByTaskId 对应的记录。
    List<SemanticSymbol> findByTaskId(@Param("taskId") UUID taskId);
}
