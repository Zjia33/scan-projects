# DeepAudit Java Agent

面向 Java/Spring 项目的 AI Agent 代码安全审计平台。用户上传 ZIP 后，系统以确定性代码解析提供真实事实，再由 Recon、Orchestrator、专业审计、Critic 和 Report Agents 自主规划、检索上下文、建立漏洞假设并生成可复核报告。

项目只做授权范围内的静态代码审查，不运行上传项目、不生成 PoC，不包含 Git 拉取、增量扫描或 CI/CD。

## 当前能力

- ZIP 上传、大小限制、Zip Slip 和压缩炸弹基础防护
- JavaParser 方法级切块、接口、参数、注解和调用方法提取；模板与配置文件按行数和字符数切窗
- JavaParser Symbol Solver 全局符号索引、跨文件方法解析和接口实现分派
- Spring 依赖注入、MyBatis Mapper→XML SQL、持久化字段→模板输出语义补边
- 面向七类漏洞的受限跨过程 Source→Sink→Guard 数据流和路径覆盖置信度
- Java、XML、HTML、JSP、Vue、JavaScript、TypeScript、YAML 等文本索引
- OpenAI-compatible 批量远程 Embedding
- 语义向量、关键词、代码符号和同文件关系混合检索
- Recon Agent：理解项目架构、攻击面和已有安全机制
- Orchestrator Agent：按代码目标制定专业 Agent 审计计划
- SQL 注入、权限与越权、存储 XSS、验证绕过、资金安全专业 Agents
- 受控多轮工具调用，返回真实代码块而不是只有文件名
- Critic Agent：主动寻找全局权限、参数化查询、归属校验等反证
- Report Agent：仅依据确认结果生成管理摘要和覆盖说明
- Agent 运行、工具调用、漏洞假设和模型调用次数持久化
- 文件、行号、代码块 ID 和证据引用真实性校验
- MyBatis 持久层与 Flyway 数据库版本管理
- Web 控制台、Agent 审计日志、HTML 和 JSON 报告

## Agent 工作流

```text
安全解压 ZIP
  → 确定性 Recon 和语义索引
  → 跨文件调用图和轻量安全数据流
  → Recon Agent 理解架构
  → Orchestrator Agent 制定计划
  → 专业 Agents 多轮调用代码工具
  → 形成结构化漏洞假设
  → Critic Agent 寻找反证
  → 文件和行号校验
  → Report Agent 汇总报告
```

原有七类固定规则不再直接写入漏洞表，只负责产生 `AuditHint` 风格的调查线索。即使没有规则命中，Orchestrator 仍可以从方法、接口和语义代码中安排 AI 调查任务。

## 运行环境

本地电脑需要：

- JDK 17
- Maven 3.9
- 可访问的 OpenAI-compatible Chat Completions 服务
- 可访问的 OpenAI-compatible Embeddings 服务

默认使用 PostgreSQL。应用会自动读取项目根目录的 `.env`，也支持使用同名的操作系统环境变量覆盖配置。首次运行可复制 `.env.example` 为 `.env`，然后填写真实连接信息：

```text
DEEPAUDIT_DATASOURCE_URL=jdbc:postgresql://localhost:5432/deepaudit
DEEPAUDIT_DATASOURCE_USERNAME=deepaudit
DEEPAUDIT_DATASOURCE_PASSWORD=<由运行环境提供>
```

`.env` 已加入 `.gitignore`，不得强制提交；`.env.example` 只保存无效占位值。远程数据库端口应只放行受信任来源，不要把真实地址、用户名、密码或模型 API Key 写入受版本控制的配置文件。

## AI 与 Embedding 配置

```yaml
deepaudit:
  ai:
    required: true
    base-url: http://localhost:11434/v1
    api-key: ${DEEPAUDIT_AI_API_KEY:}
    model: qwen2.5-coder:14b
    connect-timeout-seconds: 10
    read-timeout-seconds: 120
    json-repair-attempts: 2
    max-iterations-per-agent: 6
    max-tool-calls-per-agent: 10
    planner-batch-size: 12
    max-audit-targets: 200
  embedding:
    provider: remote
    base-url: http://localhost:11434/v1
    api-key: ${DEEPAUDIT_EMBEDDING_API_KEY:}
    model: nomic-embed-text
  semantic:
    enabled: true
    max-call-depth: 10
    max-paths-per-entry: 20
    max-states-per-entry: 1000
```

模型服务需要支持：

```text
POST {base-url}/chat/completions
POST {base-url}/embeddings
```

AI 是完整扫描的必要条件。Chat 模型不可用、返回无法解析的 JSON 或 Embedding 失败时，任务会进入 `FAILED`，不会退化为规则扫描后仍显示成功。

修改模型配置后需要重启应用。

## 启动

```powershell
mvn spring-boot:run
```

浏览器打开：

```text
http://localhost:8080/
```

应用第一次连接空数据库时，Flyway 会依次执行：

- `V1__initial_schema.sql`：核心项目、任务、代码块和漏洞表
- `V2__add_query_indexes.sql`：查询索引
- `V3__add_agent_audit_schema.sql`：Agent 运行、事件、假设、AI 摘要及代码语义元数据
- `V4__add_semantic_analysis_schema.sql`：全局符号、跨文件调用边和安全数据流路径

## Agent 只读工具

专业 Agent 只能选择以下受控工具，不能执行 Shell、网络请求或上传项目代码：

- `get_chunk`
- `hybrid_search`
- `call_context`
- `get_call_chain`
- `trace_data_flow`
- `find_security_guards`
- `security_controls`
- `data_access`

上传源码始终作为不可信数据传递给模型。Agent 提交的主证据和关联证据必须来自当前目标或工具返回的代码块 ID，否则候选会被拒绝。

## API

- `POST /api/projects/upload`：上传 ZIP
- `GET /api/tasks`：任务列表和 Agent 调用统计
- `GET /api/tasks/{taskId}`：任务进度
- `GET /api/tasks/{taskId}/agents`：Agent 运行记录
- `GET /api/tasks/{taskId}/events`：Agent 操作摘要和工具日志
- `GET /api/tasks/{taskId}/hypotheses`：漏洞假设及 Critic 状态
- `GET /api/tasks/{taskId}/findings`：确认漏洞列表
- `GET /api/tasks/{taskId}/report.html`：HTML 报告
- `GET /api/tasks/{taskId}/report.json`：包含 Agent 信息的 JSON 报告

## 验证

```powershell
mvn test
mvn clean package
```

测试环境使用确定性的测试 LLM Gateway 和本地哈希 Embedding，但仍完整经过 Recon、规划、专业 Agent、工具调用、Critic 和 Report 协议，不会通过关闭 AI 绕过 Agent 工作流。

### 在 IDEA 中测试真实对话模型和嵌入模型

1. 打开 `src/test/resources/application-model-api-test.yml`。
2. 在 `deepaudit.ai` 下填写对话模型的 `base-url`、`api-key` 和 `model`。
3. 在 `deepaudit.embedding` 下填写嵌入模型配置。文件中已经预填硅基流动 `BAAI/bge-m3`，只需替换 API Key。
4. 打开 `src/test/java/com/deepaudit/ModelApiManualIT.java`。
5. 点击类名左侧绿色按钮运行全部测试，或者点击某个测试方法左侧按钮单独运行。

可单独运行的方法：

- `conversationModelRecognizesSqlInjectionAndReturnsAgentJson`：打印 Orchestrator 和专业 Agent 的结构化 JSON，并验证模型能够识别示例中的 SQL 注入。
- `embeddingModelRanksSecurityRelatedCodeAboveUnrelatedCode`：打印向量维度、相关代码相似度、无关代码相似度及差值。

测试使用 H2 且关闭 Flyway，不会连接或修改云端 PostgreSQL。测试类以 `IT` 结尾，普通 `mvn test` 不会自动运行它，避免意外调用付费 API；仍可通过 IDEA 绿色按钮随时运行。
