package com.deepaudit.mapper;

import com.deepaudit.domain.SemanticSymbol;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.UUID;

public interface SemanticSymbolMapper {
    int deleteByTaskId(@Param("taskId") UUID taskId);
    int insertBatch(@Param("symbols") List<SemanticSymbol> symbols);
    List<SemanticSymbol> findByTaskId(@Param("taskId") UUID taskId);
}
