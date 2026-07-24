# DeepAudit Java Agent

面向 Java/Spring 项目的 AI Agent 代码安全审计平台。用户导入 Git 仓库并选择提交后，系统以确定性代码解析提供真实事实，再由 Recon、Orchestrator、专业审计、Critic 和 Report Agents 自主规划、检索上下文、建立漏洞假设并生成可复核报告。

项目只做授权范围内的静态代码审查，不运行仓库代码、不生成 PoC、不触发 Hook/Submodule/LFS/构建脚本，也不包含 CI/CD。系统支持对单个不可变提交执行全量扫描，以及比较两个不可变提交的增量安全审计。

## 当前能力

- 只读导入 HTTPS Git 仓库、列出提交并安全物化不可变提交快照
- 单提交全量扫描，以及 Base/Target 双提交增量扫描
- JavaParser 将 Git Diff 行区间映射为方法级变更块，并通过跨文件调用图双向扩展两层影响范围
- 增量任务只为直接变更块和语义影响块生成必要 Embedding，同时保留完整 Target 项目事实
- 按模型、输入内容哈希复用 Embedding；漏洞使用独立于行号的稳定指纹
- Critic 将目标提交中的确认问题标记为新增、回归、持续存在或受变更影响；全量结果标记为基线
- JavaParser 方法级切块、接口、参数、注解和调用方法提取；模板与配置文件按行数和字符数切窗
- JavaParser Symbol Solver 全局符号索引、跨文件方法解析和接口实现分派
- Spring 依赖注入、MyBatis Mapper→XML SQL、持久化字段→模板输出语义补边
- 面向七类漏洞的受限跨过程 Source→Sink→Guard 数据流和路径覆盖置信度
- Java、XML、HTML、JSP、Vue、JavaScript、TypeScript、YAML 等文本索引
- OpenAI-compatible 批量远程 Embedding
- PostgreSQL pgvector + HNSW 余弦近邻召回，并结合关键词、代码符号和同文件关系重排
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
安全物化 Git 提交快照
  → 全量项目事实或增量 ChangeSet
  → 确定性 Recon 和语义索引
  → 增量模式扩展调用方、被调用方、接口与安全配置影响面
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
- IDEA 中启用 Lombok 插件和 Annotation Processing（仅 IDE 代码提示需要，Maven 会自动处理）
- 可访问的 OpenAI-compatible Chat Completions 服务
- 可访问的 OpenAI-compatible Embeddings 服务
- PostgreSQL 13+，并在目标数据库中启用 pgvector 0.8+
- 可访问的、已经获得审计授权的 HTTPS Git 仓库

默认使用 PostgreSQL。应用会自动读取项目根目录的 `.env`，也支持使用同名的操作系统环境变量覆盖配置。首次运行可复制 `.env.example` 为 `.env`，然后填写真实连接信息：

```text
DEEPAUDIT_DATASOURCE_URL=jdbc:postgresql://localhost:5432/deepaudit
DEEPAUDIT_DATASOURCE_USERNAME=deepaudit
DEEPAUDIT_DATASOURCE_PASSWORD=<由运行环境提供>
DEEPAUDIT_EMBEDDING_DIMENSIONS=1024
DEEPAUDIT_VECTOR_STORE_PROVIDER=pgvector
DEEPAUDIT_GIT_ALLOWED_HOSTS=github.com,gitlab.com,gitee.com
```

`.env` 已加入 `.gitignore`，不得强制提交；`.env.example` 只保存无效占位值。远程数据库端口应只放行受信任来源，不要把真实地址、用户名、密码或模型 API Key 写入受版本控制的配置文件。

pgvector 必须在 DeepAudit 实际连接的数据库中启用，而不只是安装到 PostgreSQL 服务器：

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

Flyway 的 `V9` 迁移也会执行这条语句。若应用数据库账号没有创建扩展的权限，请先用数据库管理员账号执行一次。

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
    dimensions: 768
  vector-store:
    provider: pgvector
    hnsw-ef-search: 100
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

AI 是完整审计流程的必要条件。Chat 模型不可用、返回无法解析的 JSON 或 Embedding 失败时，任务会进入 `FAILED`，不会退化为规则扫描后仍显示成功。

`deepaudit.embedding.dimensions` 必须与模型实际返回维度一致，并且会用于创建
`code_chunk.embedding_vector vector(n)`。修改模型或维度后不能直接复用原来的向量列；
需要新增数据库迁移或重建开发数据库后重新扫描。修改配置后需要重启应用。

代码块的原始序列化 Embedding 仍保留在 `code_chunk.embedding`，用于缓存兼容和诊断；
实际召回使用 `embedding_vector`、余弦距离运算符 `<=>` 和 HNSW 索引在 PostgreSQL
内部完成。Java 层只对数据库返回的候选执行关键词和确定性结构关系重排，不再逐块计算向量距离。

## Git 仓库安全边界

后端通过 JGit 克隆只读裸仓库，并直接读取 Git Tree/Blob 物化提交快照，不调用系统 Git，也不执行 Checkout 过滤器。以下内容不会被执行或自动获取：

- Git Hook
- Submodule
- Git LFS Filter
- 构建脚本、测试或仓库内可执行文件
- 目标项目依赖安装

代码盘点默认只保留可审计的生产源码和配置。`src/test`、`tests`、`__tests__`、集成测试、
测试夹具、`*Test.java`、`*IT.java`、构建输出、生成代码、依赖目录、文档目录和压缩后的前端
Bundle 不会物化到分析快照，也不会生成 Chunk、Embedding、语义关系、增量变更或 Agent 任务。
`pom.xml`、生产环境 XML/YAML/Properties、MyBatis Mapper 和数据库迁移仍会保留。

生产环境只允许 `deepaudit.git.allowed-hosts` 中的 HTTPS 主机。私有仓库令牌只在导入或刷新请求内使用，不写入数据库、日志和 API 响应。本地 `file:` 仓库只在测试配置显式开启。

全量扫描选择一个 Target Commit。增量扫描要求 Base 是 Target 的祖先，并同时保存 Base、Target 和 Merge Base 的完整 SHA。系统仍解析 Target 的完整项目结构、配置和 Java 语义图，但专业 Agent 的深度目标限制为直接变更块、两层调用影响块以及全局安全配置相关块。

增量报告只对 Target 中仍可验证的漏洞分类：`NEW` 表示本次变更新增，`REGRESSED` 表示防护被削弱，`PERSISTING` 表示 Base 与 Target 均存在，`AFFECTED` 表示漏洞位于调用影响范围。删除文件和删除行会保留在 ChangeSet 中，但当前不会单独生成 `FIXED` 漏洞项，因为 Target 中已不存在可通过 Critic 证据门禁的主代码块。

Base/Target 临时快照只在分析期间存在；任务完成或失败后会清理。裸仓库、完整提交 SHA、结构化 Diff、代码块、Agent 轨迹和报告结果会保留。

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
- `V5__merge_authorization_vulnerability_types.sql`：统一越权漏洞类型
- `V6__add_git_incremental_audit.sql`：Git 来源、提交范围、结构化 Diff 和增量 Chunk 元数据
- `V7__add_embedding_cache.sql`：按模型与输入哈希复用 Embedding
- `V8__add_finding_fingerprint.sql`：稳定漏洞指纹
- `V9__add_pgvector_recall.sql`：启用 pgvector、增加定维向量列并创建 HNSW 余弦索引

## Agent 只读工具

专业 Agent 只能选择以下受控工具，不能执行 Shell、网络请求或仓库代码：

- `get_chunk`
- `hybrid_search`
- `call_context`
- `get_call_chain`
- `trace_data_flow`
- `find_security_guards`
- `security_controls`
- `data_access`

仓库源码始终作为不可信数据传递给模型。Agent 提交的主证据和关联证据必须来自当前目标或工具返回的代码块 ID，否则候选会被拒绝。增量任务还要求 Critic 验证漏洞与直接变更或语义影响链之间的因果关系。

## API

- `POST /api/projects/git`：只读导入 Git 仓库并返回提交记录
- `GET /api/projects`：已导入 Git 仓库列表
- `GET /api/projects/{projectId}/commits`：读取本地裸仓库中的提交记录
- `POST /api/projects/{projectId}/refresh`：使用本次请求中的可选令牌刷新远端
- `POST /api/projects/{projectId}/audits`：创建全量或增量审计任务
- `GET /api/tasks`：任务列表和 Agent 调用统计
- `GET /api/tasks/{taskId}`：任务进度
- `GET /api/tasks/{taskId}/agents`：Agent 运行记录
- `GET /api/tasks/{taskId}/events`：Agent 操作摘要和工具日志
- `GET /api/tasks/{taskId}/hypotheses`：漏洞假设及 Critic 状态
- `GET /api/tasks/{taskId}/changes`：结构化 Git 文件和行范围差异
- `GET /api/tasks/{taskId}/findings`：确认漏洞列表
- `GET /api/tasks/{taskId}/report.html`：HTML 报告
- `GET /api/tasks/{taskId}/report.json`：包含 Agent 信息的 JSON 报告

导入仓库：

```json
{
  "name": "订单中心",
  "repositoryUrl": "https://github.com/example/order-service.git",
  "username": "GitHub 用户名；公开仓库可省略",
  "accessToken": "仅随本次请求传输"
}
```

GitHub 私有仓库建议使用 fine-grained personal access token：`Resource owner` 选择仓库所属账户，
`Repository access` 选择目标仓库，并至少授予仓库级 `Contents: Read-only` 权限。令牌作为 HTTPS
密码传入；服务端会去除复制时带入的首尾空白，但不会持久化、记录或回显令牌。

创建全量任务时提交 `{"scanMode":"FULL","targetCommit":"<sha>"}`；创建增量任务时提交 `{"scanMode":"INCREMENTAL","baseCommit":"<sha>","targetCommit":"<sha>"}`。服务端会把修订解析并固化为完整提交 SHA。

## 验证

```powershell
mvn test
mvn clean package
```

测试环境使用确定性的测试 LLM Gateway、本地哈希 Embedding 和内存向量召回替身，但仍完整经过 Recon、规划、专业 Agent、工具调用、Critic 和 Report 协议，不会通过关闭 AI 绕过 Agent 工作流。生产环境默认且只应使用 `pgvector` 召回。

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
