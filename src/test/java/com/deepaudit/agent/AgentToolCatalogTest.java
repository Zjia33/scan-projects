package com.deepaudit.agent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AgentToolCatalogTest {

    @Test
    void promptIsConciseAndKeepsSelectionAndEvidenceRules() {
        String prompt = AgentToolCatalog.prompt();

        assertThat(prompt)
                .contains("工具选择：", "read_source", "verify_relation", "search_symbols", "search_code")
                .contains("explore_call_graph", "get_change_context", "resolve_data_access")
                .contains("inspect_security_policy", "trace_value")
                .contains("候选流程：搜索 -> read_source", "需要引用时 verify_relation")
                .contains("证据资格不等于漏洞成立", "EMPTY 不是反证")
                .contains("INVALID/DENIED/ERROR 不形成新证据")
                .contains("TOOL_RESULT_TRUNCATED", "OBSERVATION_TRUNCATED", "ITEM_TRUNCATED")
                .hasSizeLessThan(10_000);
    }

    @Test
    void descriptionsKeepImportantRuntimeSemantics() {
        assertThat(description(AgentToolCatalog.READ_SOURCE))
                .contains("文件绝对行号", "最多160行", "候选读取后仍是 candidateChunkIds");
        assertThat(description(AgentToolCatalog.SEARCH_CODE))
                .contains("CURRENT_FILE|RELATED|PROJECT", "单个字面量", "不支持正则")
                .contains("相交或相邻的上下文窗口会合并")
                .contains("\"permitAll\"", "\"**/*Security*.java\"");
        assertThat(description(AgentToolCatalog.EXPLORE_CALL_GRAPH))
                .contains("depth(int，1..3，默认2");
        assertThat(description(AgentToolCatalog.GET_CHANGE_CONTEXT))
                .contains("只匹配 Base/Target 路径、符号和方法名")
                .contains("includeConfiguration(boolean，默认false)", "文件最多返回3个相关 hunk");
        assertThat(description(AgentToolCatalog.RESOLVE_DATA_ACCESS))
                .contains("完全没有可达结果时退回项目搜索")
                .contains("语法指标本身不能确认或排除漏洞");
        assertThat(description(AgentToolCatalog.TRACE_VALUE))
                .contains("多项为 AND", "优先级 variable、source、sink")
                .contains("ARGUMENT_MAPPING 只证明局部参数传递");
    }

    @Test
    void symbolSearchDefinesFormatAndExamplesForEveryStringFilter() {
        String description = description(AgentToolCatalog.SEARCH_SYMBOLS);

        assertThat(description)
                .contains("symbol：类/方法/Class#method/限定名/签名片段")
                .contains("\"OrderService#load\"", "不要传 \"service.load(id)\"")
                .contains("kind：优先复用 target.chunkType 或结果 kind")
                .contains("\"JAVA_METHOD\"", "\"MYBATIS_SQL\"", "不是固定枚举")
                .contains("annotation：注解名或稳定片段")
                .contains("\"PreAuthorize\"", "不要传自然语言")
                .contains("filePath：使用 / 的项目相对路径或片段")
                .contains("endpoint：路由路径或片段", "不含 HTTP 方法和域名")
                .contains("至少填一项，多项为 AND")
                .contains("示例 arguments：{\"symbol\":\"OrderService#load\",\"kind\":\"JAVA_METHOD\",\"limit\":5}");
    }

    @Test
    void freeTextSelectorsDefineTheirCorpusAndCombinationRules() {
        assertThat(description(AgentToolCatalog.GET_CHANGE_CONTEXT))
                .contains("查方法变化时用方法名/Class#method/路径")
                .contains("只匹配 Base/Target 路径、符号和方法名")
                .contains("查文件变化时还可用 changeType 或 diff 字面量", "多词为 OR");
        assertThat(description(AgentToolCatalog.RESOLVE_DATA_ACCESS))
                .contains("路径、符号、endpoint、类型、参数、注解、被调符号和源码")
                .contains("分词 OR 匹配", "不要传自然语言");
        assertThat(description(AgentToolCatalog.TRACE_VALUE))
                .contains("source/sink 优先复用 semanticEvidence/TOOL_RESULT")
                .contains("variable 用标识符", "多项为 AND")
                .contains("优先级 variable、source、sink");
    }

    @Test
    void everyAllowedArgumentIsDocumentedAndEveryToolHasAJsonExample() {
        for (AgentToolCatalog.ToolSpec spec : AgentToolCatalog.specs()) {
            assertThat(spec.description())
                    .as("tool %s should include a usable arguments example", spec.name())
                    .contains("示例 arguments：");
            for (String argument : spec.allowedArguments()) {
                assertThat(spec.description())
                        .as("tool %s should document argument %s", spec.name(), argument)
                        .contains(argument);
            }
        }
    }

    private String description(String name) {
        return AgentToolCatalog.find(name).description();
    }
}
