# DeepAudit Java Agent

面向 Java/Spring 项目的 AI Agent 代码安全审计平台。用户导入 Git 仓库并选择提交后，系统以确定性代码解析提供真实事实，再由 Recon、Orchestrator、专业审计、Critic 和 Report Agents 自主规划、检索上下文、建立漏洞假设并生成可复核报告。

项目只做授权范围内的静态代码审查，不运行仓库代码、不生成 PoC、不触发 Hook/Submodule/LFS/构建脚本，也不包含 CI/CD。系统只支持比较两个不可变提交的增量安全审计。

## 当前能力

- 只读导入 HTTPS Git 仓库，以及显式白名单中的内网 HTTP Git 仓库，列出提交并安全物化不可变提交快照
- 扫描项目基本信息维护、项目级扫描历史、归档/恢复和扫描派生数据清理
- Base/Target 分支变更审计；分支分叉时自动使用共同祖先作为实际比较基线
- 同时建立 Base/Target Java 方法索引，按完整签名、重命名路径、所属类型、位置和方法体相似度建立稳定对应
- 将增量语义变化分类为方法新增、修改、删除、签名变化、Guard 新增和 Guard 删除，纯删除行不再依赖 Target 新增行范围
- Git Diff 行区间与方法语义差异共同确定变更块，由 Base/Target CodeGraph 索引计算跨文件影响范围
- 增量任务只深入调查直接变更块和语义影响块，同时保留完整 Target 项目事实
- 漏洞使用独立于行号的稳定指纹进行跨扫描匹配
- Critic 只输出本次变更新增或 Base/Target 持续存在的确认结果
- JavaParser 方法级切块、接口、参数、注解和调用方法提取；模板与配置文件按行数和字符数切窗
- JavaParser 只解析 CHANGED/IMPACTED 及直接上下文，验证 CodeGraph 调用现场并提取参数流、Guard 和框架语义
- Spring 依赖注入、MyBatis Mapper→XML SQL、持久化字段→模板输出语义补边
- 面向五类新任务漏洞的受限跨过程 Source→Sink→Guard 数据流和路径覆盖置信度
- 统一文件角色白名单：索引 Java 后端源码、运行与安全配置、MyBatis/SQL、服务端模板；构建描述只用于架构识别
- Markdown、独立前端源码与静态资源在 Git 快照物化前即被忽略，不进入 Diff、分块、语义分析或模型上下文
- Recon Agent：只读取去计数后的框架事实、构建描述和 application/bootstrap 配置，生成技术架构摘要；不接收普通业务源码或增量作用域
- Triage Orchestrator：对紧凑审计单元执行 `INVESTIGATE / NEED_CONTEXT / SKIP` 三态轻量分流
- `NEED_CONTEXT` 单元按需补充调用链、安全流和相关代码位置后复判
- 只有 `INVESTIGATE` 单元创建 SQL 注入、权限、敏感信息泄露、XSS 或验证绕过专业 Agent
- SQL 注入、越权、敏感信息泄露、存储 XSS、验证绕过五类独立专业 Agents
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
  → Base/Target ChangeSet
  → Base/Target 方法索引、稳定方法映射和六类语义差异
  → 确定性技术栈、项目结构画像和语义索引
  → CodeGraph 扩展调用方、被调用方和安全配置影响面
  → JavaParser 在作用域内验证调用现场并构建轻量安全数据流
  → Recon Agent 读取构建描述、application/bootstrap 配置和去计数框架事实，归纳技术架构
  → 按入口、危险操作、安全配置、变更和语义流构建紧凑审计单元
  → Triage Orchestrator 三态轻量分流
  → NEED_CONTEXT 定向补充调用链和安全上下文后复判
  → 专业 Agents 多轮调用代码工具
  → 形成结构化漏洞假设
  → Critic Agent 寻找反证
  → 文件和行号校验
  → Report Agent 汇总报告
```

原有七类固定规则不再直接写入漏洞表，只负责产生 `AuditHint` 风格的调查线索。规则线索和已经形成的语义安全流属于必审单元，不能因模型漏返回而被跳过；其他外部入口、危险操作、安全配置和增量影响代码先经过轻量分流。普通 Getter、DTO 样板方法和没有安全相关事实的孤立代码不会作为独立审计单元发送给模型，但专业 Agent 仍可通过只读工具按需获取调用链上下文。

编排范围不再使用“前 300 个代码块”作为选择策略。系统会覆盖全部安全相关审计单元，`triage-batch-size` 只控制每次轻量模型请求的摘要数量，不截断项目总范围；真正昂贵的完整代码、语义工具和多轮推理只提供给 `INVESTIGATE` 单元。

## 运行环境

本地电脑需要：

- JDK 17
- Maven 3.9
- IDEA 中启用 Lombok 插件和 Annotation Processing（仅 IDE 代码提示需要，Maven 会自动处理）
- 可访问的 OpenAI-compatible Chat Completions 服务
- PostgreSQL 13+
- 可访问的、已经获得审计授权的 Git 仓库；默认要求 HTTPS，仅显式白名单内网主机可使用 HTTP

默认使用 PostgreSQL。应用会自动读取项目根目录的 `.env`，也支持使用同名的操作系统环境变量覆盖配置。首次运行可复制 `.env.example` 为 `.env`，然后填写真实连接信息：

```text
DEEPAUDIT_DATASOURCE_URL=jdbc:postgresql://localhost:5432/deepaudit
DEEPAUDIT_DATASOURCE_USERNAME=deepaudit
DEEPAUDIT_DATASOURCE_PASSWORD=<由运行环境提供>
DEEPAUDIT_GIT_ALLOWED_HOSTS=github.com,gitlab.com,gitee.com
DEEPAUDIT_GIT_ALLOWED_HTTP_HOSTS=
```

`.env` 已加入 `.gitignore`，不得强制提交；`.env.example` 只保存无效占位值。远程数据库端口应只放行受信任来源，不要把真实地址、用户名、密码或模型 API Key 写入受版本控制的配置文件。

## AI 配置

```yaml
deepaudit:
  ai:
    base-url: https://api.deepseek.com
    api-key: ${DEEPAUDIT_AI_API_KEY:}
    model: deepseek-v4-flash
    connect-timeout-seconds: 10
    read-timeout-seconds: 120
    json-repair-attempts: 2
    max-iterations-per-agent: 6
    max-tool-calls-per-agent: 10
    professional-agent-parallelism: 4
    professional-agent-queue-capacity: 1000
    triage-batch-size: 20
  semantic:
    enabled: true
    max-call-depth: 10
    max-paths-per-entry: 20
    max-states-per-entry: 1000
```

模型服务需要支持：

```text
POST {base-url}/chat/completions
```

AI 是完整审计流程的必要条件。Chat 模型不可用或返回无法解析的 JSON 时，任务会进入 `FAILED`，不会退化为规则扫描后仍显示成功。

## CodeGraph 全局拓扑

DeepAudit 通过 [CodeGraph](https://github.com/colbymchenry/codegraph) 的本地 CLI 提供跨文件全局调用拓扑，
JavaParser 不再构建第二套全项目调用图。CodeGraph 只决定影响范围和关系候选，不直接判定漏洞。
CodeGraph 必须安装在运行 DeepAudit 的机器或容器内；
可以从 `PATH` 调用，也可以配置 Windows 官方发行包的解压根目录。无需为被审计项目单独执行
`codegraph init`。增量任务会在不可变 Comparison Base 和 Target 快照中分别建立临时索引：Target
用于当前影响范围和作用域关系，Base 用于删除方法、签名变化和历史调用者。

Windows 官方发行包无需执行安装程序。保持压缩包内的 `node.exe`、`bin` 和 `lib` 相对布局不变，
然后将解压根目录写入 `DEEPAUDIT_CODEGRAPH_BUNDLE_ROOT`。DeepAudit 会直接调用内置 Node 和 CLI
脚本，不经过 `codegraph.cmd` 或 `cmd.exe`。

已有 Node.js 时可按上游说明安装：

```powershell
npm install -g @colbymchenry/codegraph
codegraph version
```

也可以使用 CodeGraph 官方发布的独立安装包。DeepAudit 只调用 CLI，不需要运行交互式
`codegraph install`，也不需要配置 MCP。生产环境建议把 `codegraph version` 的完整输出写入
`DEEPAUDIT_CODEGRAPH_EXPECTED_VERSION`，避免升级后命令或 JSON 协议变化被静默接受。

生产配置启用 CodeGraph：

```text
DEEPAUDIT_CODEGRAPH_ENABLED=true
DEEPAUDIT_CODEGRAPH_EXECUTABLE=codegraph
DEEPAUDIT_CODEGRAPH_BUNDLE_ROOT=
DEEPAUDIT_CODEGRAPH_EXPECTED_VERSION=<codegraph version 的完整输出>
```

CodeGraph 是唯一的全局拓扑主来源，生产环境没有降级模式；Base/Target 索引或必要关系查询失败会使任务失败。`enabled=false` 仅用于使用确定性替身的自动化测试配置。

CodeGraph 返回的直接关系先标记为候选。JavaParser 仅在调用方局部 AST 中找到唯一调用现场时，将其
提升为 `CODEGRAPH_VERIFIED` 并补充实参到形参映射；歧义关系保持 `CODEGRAPH_CANDIDATE`，不能进入
安全流或通过 `verify_relation` 证据门禁。CLI 通过参数数组启动而非 Shell，禁用遥测、提示 Hook 和
守护进程；两个索引分别写入 Base/Target 任务快照内的单级相对目录，并在任务结束时随快照清理。

## Git 仓库安全边界

后端通过 JGit 克隆只读裸仓库，并直接读取 Git Tree/Blob 物化提交快照，不调用系统 Git，也不执行 Checkout 过滤器。以下内容不会被执行或自动获取：

- Git Hook
- Submodule
- Git LFS Filter
- 构建脚本、测试或仓库内可执行文件
- 目标项目依赖安装

代码盘点使用统一的文件角色白名单，只保留可审计的 Java 生产源码、安全与运行配置、
MyBatis/SQL、服务端模板和构建描述。`src/test`、`tests`、`__tests__`、集成测试、测试夹具、
`*Test.java`、`*IT.java`、构建输出、生成代码、依赖目录、Markdown、独立前端源码、样式和
静态 HTML 不会物化到分析快照，也不会生成 Diff、Chunk、语义关系或 Agent 任务。
`pom.xml`/Gradle 描述只参与架构识别，不生成 Chunk；application/bootstrap 配置、受支持的
安全 XML、MyBatis Mapper、数据库迁移以及 JSP/FreeMarker/Thymeleaf 服务端模板仍会保留。

生产环境只允许 `deepaudit.git.allowed-hosts` 中的主机，并默认强制 HTTPS。只有同时出现在 `deepaudit.git.allowed-hosts` 和 `deepaudit.git.allowed-http-hosts` 中的精确主机名才允许使用 HTTP；不支持通配符或子域名隐式匹配。私有仓库令牌只在导入或刷新请求内使用，不写入数据库、日志和 API 响应。本地 `file:` 仓库只在测试配置显式开启。

每次审计都必须选择基准分支提交和目标分支提交，并同时保存所选 Base、Target 和 Merge Base 的完整 SHA；若两个分支已经分叉，系统自动以 Merge Base 作为实际比较基线，只分析目标分支自共同祖先以来引入的变化。系统保留 Target 的完整项目结构和配置上下文，同时为实际比较基线和 Target 建立独立 CodeGraph 与方法快照索引。方法通过完整签名优先匹配，签名变化再使用重命名路径、所属类型、源码位置和方法体相似度建立唯一对应。专业 Agent 的深度目标限制为直接变更块、CodeGraph 影响块以及全局安全配置相关块，范围扩展不按固定代码块数量截断。

增量报告只对 Target 中仍可验证的漏洞分类：`NEW` 表示本次变更直接引入、防护削弱或调用影响导致的确认问题，`PERSISTING` 表示有明确证据证明漏洞在 Base 与 Target 中均存在。纯删除行通过 Base/Target 方法正文比较定位到 Target 方法；被删除方法会保存独立语义变化，并通过剩余调用者和同文件方法扩展影响范围。当前仍不单独生成 `FIXED` 漏洞项，因为 Target 中已不存在可通过 Critic 证据门禁的主代码块。

Base/Target 临时快照只在分析期间存在；任务完成或失败后会清理。裸仓库、完整提交 SHA、结构化 Diff、代码块、Agent 轨迹和报告结果会保留。

## 启动

```powershell
mvn spring-boot:run
```

浏览器打开：

```text
http://localhost:8080/
```

应用第一次连接空数据库时，Flyway 会执行单个 `V1__initial_schema.sql`，一次性创建当前版本需要的项目、任务、代码块、漏洞、Agent 轨迹、Git 差异和语义分析表，以及对应索引、外键和检查约束。该初始化脚本只面向全新数据库，不兼容旧版数据库的原地升级。

当前数据库结构不使用 RAG、Embedding、向量召回或 pgvector。部署时无需安装 PostgreSQL `vector` 扩展。

## Agent 只读工具

专业 Agent 只能选择以下受控工具，不能执行 Shell、网络请求或仓库代码：

- `get_chunk({chunkId})`：读取指定代码块
- `verify_relation({candidateChunkId})`：验证候选与当前目标的确定性关系
- `call_context({})`：读取直接调用和同文件候选上下文
- `get_call_chain({})`：读取已有语义安全流或调用出边
- `trace_data_flow({})`：读取当前漏洞类型的 Source-to-Sink 路径
- `find_security_guards({})`：读取路径上的权限、租户和验证控制
- `search_symbols({symbol,kind,annotation,filePath,endpoint,text})`：确定性检索符号和代码位置
- `explore_call_graph({direction,depth,targetChunkId,targetSymbol})`：按方向和深度探索调用路径
- `get_change_context({selector,includeConfiguration})`：读取 Base/Target 方法和文件差异
- `resolve_data_access({selector,depth})`：解析 Mapper、Repository、SQL 与参数绑定
- `inspect_security_policy({endpoint})`：检查方法安全注解和匹配入口的全局规则
- `trace_value({source,sink,variable,depth})`：定向追踪安全流和跨调用参数映射

模型只通过结构化 `arguments` 调用工具，结果数量使用 `arguments.limit` 控制。确定性符号搜索、同文件上下文和未映射的 CodeGraph 结果只用于发现候选，必须通过 `verify_relation` 后才能作为漏洞证据。仓库源码始终作为不可信数据传递给模型。Agent 提交的主证据和关联证据必须来自当前目标或工具返回的已验证代码块 ID，否则候选会被拒绝。增量任务还要求 Critic 验证漏洞与直接变更或语义影响链之间的因果关系。

## API

- `POST /api/projects/git`：只读导入 Git 仓库并返回提交记录
- `GET /api/projects`：使用中的 Git 项目列表；`includeArchived=true` 时包含归档项目
- `GET /api/projects/{projectId}`：项目基本信息
- `PATCH /api/projects/{projectId}`：修改项目名称和描述
- `POST /api/projects/{projectId}/archive`：归档没有运行中任务的项目
- `POST /api/projects/{projectId}/restore`：恢复归档项目
- `GET /api/projects/{projectId}/audits`：项目扫描历史
- `POST /api/projects/{projectId}/cleanup`：清理归档项目的扫描派生数据
- `GET /api/projects/{projectId}/commits`：读取本地裸仓库中的提交记录
- `POST /api/projects/{projectId}/refresh`：使用本次请求中的可选令牌刷新远端
- `POST /api/projects/{projectId}/audits`：创建 Base→Target 增量审计任务
- `GET /api/tasks`：任务列表和 Agent 调用统计
- `GET /api/tasks/{taskId}`：任务进度
- `POST /api/tasks/{taskId}/cancel`：中断尚未进入终态的审计任务
- `GET /api/tasks/{taskId}/agents`：Agent 运行记录
- `GET /api/tasks/{taskId}/events`：Agent 操作摘要和工具日志
- `GET /api/tasks/{taskId}/events/stream`：任务实时事件流（SSE）
- `GET /api/tasks/{taskId}/hypotheses`：漏洞假设及 Critic 状态
- `GET /api/tasks/{taskId}/changes`：结构化 Git 文件和行范围差异
- `GET /api/tasks/{taskId}/method-changes`：Base/Target 方法级语义变化和前后代码证据
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

创建任务时提交 `{"baseCommit":"<sha>","targetCommit":"<sha>"}`。Base 和 Target 均为必填且不能相同，服务端会把修订解析并固化为完整提交 SHA。

归档只会阻止仓库刷新和新建扫描，不会删除仓库或历史报告。数据清理必须先归档项目，且请求体必须包含
`{"confirmation":"DELETE_SCAN_DATA"}`；清理会级联删除该项目的扫描任务、代码块、语义关系、
Agent 轨迹、漏洞和报告，但保留项目基本信息与本地裸 Git 仓库，项目恢复后仍可继续扫描。

## 验证

```powershell
mvn test
mvn clean package
```

测试环境使用确定性的测试 LLM Gateway，并完整经过 Recon、规划、专业 Agent、工具调用、Critic 和 Report 协议，不会通过关闭 AI 绕过 Agent 工作流。

### 在 IDEA 中测试真实对话模型

1. 打开 `src/test/resources/application-model-api-test.yml`。
2. 在 `deepaudit.ai` 下填写对话模型的 `base-url`、`api-key` 和 `model`。
3. 打开 `src/test/java/com/deepaudit/ModelApiManualIT.java`。
4. 点击类名左侧绿色按钮运行测试。

可单独运行的方法：

- `conversationModelRecognizesSqlInjectionAndReturnsAgentJson`：打印 Triage Orchestrator 和专业 Agent 的结构化 JSON，并验证模型能够识别示例中的 SQL 注入。

测试使用 H2 且关闭 Flyway，不会连接或修改云端 PostgreSQL。测试类以 `IT` 结尾，普通 `mvn test` 不会自动运行它，避免意外调用付费 API；仍可通过 IDEA 绿色按钮随时运行。
