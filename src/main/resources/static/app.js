const TERMINAL_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);
const state = {
    tasks: [],
    selectedTaskId: null,
    renderedTaskId: null,
    renderedFindingCount: -1,
    renderedStatus: null,
    loadingTasks: false,
    poller: null,
    eventSource: null,
    eventIdsByTask: new Map(),
    eventsByTask: new Map(),
    agentRefreshTimer: null
};

const elements = {
    form: document.querySelector('#upload-form'),
    file: document.querySelector('#zip-file'),
    fileLabel: document.querySelector('#file-label'),
    dropZone: document.querySelector('#drop-zone'),
    message: document.querySelector('#upload-message'),
    submit: document.querySelector('#submit-button'),
    refresh: document.querySelector('#refresh-button'),
    taskList: document.querySelector('#task-list'),
    taskCount: document.querySelector('#task-count'),
    detail: document.querySelector('#task-detail'),
    streamState: document.querySelector('#stream-state'),
    metricTasks: document.querySelector('#metric-tasks'),
    metricActive: document.querySelector('#metric-active'),
    metricFindings: document.querySelector('#metric-findings'),
    metricModelCalls: document.querySelector('#metric-model-calls')
};

elements.file.addEventListener('change', () => {
    elements.fileLabel.textContent = elements.file.files[0]?.name || '选择或拖入项目压缩包';
});

['dragenter', 'dragover'].forEach(type => elements.dropZone.addEventListener(type, event => {
    event.preventDefault();
    elements.dropZone.classList.add('dragging');
}));
['dragleave', 'drop'].forEach(type => elements.dropZone.addEventListener(type, event => {
    event.preventDefault();
    elements.dropZone.classList.remove('dragging');
}));
elements.dropZone.addEventListener('drop', event => {
    const file = event.dataTransfer.files[0];
    if (!file) return;
    const transfer = new DataTransfer();
    transfer.items.add(file);
    elements.file.files = transfer.files;
    elements.fileLabel.textContent = file.name;
});

elements.form.addEventListener('submit', async event => {
    event.preventDefault();
    const file = elements.file.files[0];
    if (!file || !file.name.toLowerCase().endsWith('.zip')) {
        showMessage('请选择 ZIP 文件。', true);
        return;
    }
    elements.submit.disabled = true;
    showMessage('正在上传并创建审计任务…');
    try {
        const response = await fetchJson('/api/projects/upload', {
            method: 'POST',
            body: new FormData(elements.form)
        });
        state.selectedTaskId = response.taskId;
        state.renderedTaskId = null;
        showMessage(response.message);
        elements.form.reset();
        elements.fileLabel.textContent = '选择或拖入项目压缩包';
        await loadTasks(true);
        document.querySelector('#audit-workspace').scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        showMessage(error.message, true);
    } finally {
        elements.submit.disabled = false;
    }
});

elements.refresh.addEventListener('click', () => loadTasks(true));

async function fetchJson(url, options) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || `请求失败 (${response.status})`);
    return data;
}

async function loadTasks(forceDetail = false) {
    if (state.loadingTasks) return;
    state.loadingTasks = true;
    try {
        state.tasks = await fetchJson('/api/tasks');
        if (!state.selectedTaskId && state.tasks.length) state.selectedTaskId = state.tasks[0].taskId;
        if (state.selectedTaskId && !state.tasks.some(task => task.taskId === state.selectedTaskId)) {
            state.selectedTaskId = state.tasks[0]?.taskId || null;
        }
        renderOverview();
        renderTaskList();
        const selected = selectedTask();
        if (!selected) {
            renderEmptyDetail();
            return;
        }
        if (forceDetail || state.renderedTaskId !== selected.taskId) {
            await renderSelectedTask(selected);
            return;
        }
        updateDetailSummary(selected);
        const needsFindings = selected.findingCount !== state.renderedFindingCount
            || selected.status !== state.renderedStatus;
        state.renderedStatus = selected.status;
        if (needsFindings) await refreshFindings(selected);
    } catch (error) {
        elements.taskList.replaceChildren(node('div', 'empty-state', `无法读取任务：${error.message}`));
    } finally {
        state.loadingTasks = false;
    }
}

function renderOverview() {
    elements.metricTasks.textContent = state.tasks.length;
    elements.metricActive.textContent = state.tasks.filter(task => !TERMINAL_STATUSES.has(task.status)).length;
    elements.metricFindings.textContent = state.tasks.reduce((sum, task) => sum + task.findingCount, 0);
    elements.metricModelCalls.textContent = state.tasks.reduce((sum, task) => sum + task.modelCallCount, 0);
    elements.taskCount.textContent = `${state.tasks.length} ITEMS`;
}

function renderTaskList() {
    elements.taskList.replaceChildren();
    if (!state.tasks.length) {
        elements.taskList.append(node('div', 'empty-state', '暂无审计任务'));
        return;
    }
    state.tasks.forEach((task, index) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `task-card${task.taskId === state.selectedTaskId ? ' active' : ''}`;
        button.addEventListener('click', () => selectTask(task.taskId));
        const copy = document.createElement('span');
        copy.className = 'task-copy';
        copy.title = task.projectName;
        copy.append(node('strong', '', task.projectName),
            node('small', '', `${task.currentStage} · ${task.findingCount} 个问题`));
        const status = node('span', `status-pill${task.status === 'FAILED' ? ' failed' : ''}`, statusText(task.status));
        button.append(node('span', 'task-index', String(index + 1).padStart(2, '0')), copy, status);
        elements.taskList.append(button);
    });
}

async function selectTask(taskId) {
    if (state.selectedTaskId === taskId && state.renderedTaskId === taskId) return;
    state.selectedTaskId = taskId;
    renderTaskList();
    const task = selectedTask();
    if (task) await renderSelectedTask(task);
}

function selectedTask() {
    return state.tasks.find(task => task.taskId === state.selectedTaskId);
}

async function renderSelectedTask(task) {
    const requestedTaskId = task.taskId;
    elements.detail.replaceChildren(node('div', 'empty-state', '正在加载 Agent 调查记录…'));
    try {
        const [findings, events, agents] = await Promise.all([
            task.findingCount > 0 || task.status === 'COMPLETED'
                ? fetchJson(`/api/tasks/${task.taskId}/findings`) : Promise.resolve([]),
            fetchJson(`/api/tasks/${task.taskId}/events`),
            fetchJson(`/api/tasks/${task.taskId}/agents`)
        ]);
        if (state.selectedTaskId !== requestedTaskId) return;
        seedEvents(task.taskId, events);
        elements.detail.replaceChildren(buildTaskDetail(task, findings, agents, events));
        state.renderedTaskId = task.taskId;
        state.renderedFindingCount = task.findingCount;
        state.renderedStatus = task.status;
        connectEventStream(task.taskId);
    } catch (error) {
        elements.detail.replaceChildren(node('div', 'empty-state', `无法读取任务详情：${error.message}`));
    }
}

function buildTaskDetail(task, findings, agents, events) {
    const fragment = document.createDocumentFragment();
    const head = document.createElement('div');
    head.className = 'detail-head';
    const title = document.createElement('div');
    title.append(node('h3', '', task.projectName),
        node('p', '', `${task.originalFilename} / ${formatTime(task.createdAt)}`));
    const report = document.createElement(task.status === 'COMPLETED' ? 'a' : 'span');
    report.className = `report-link${task.status === 'COMPLETED' ? '' : ' disabled'}`;
    report.textContent = task.status === 'COMPLETED' ? '打开中文报告 ↗' : '报告生成中';
    if (task.status === 'COMPLETED') {
        report.href = `/api/tasks/${task.taskId}/report.html`;
        report.target = '_blank';
        report.rel = 'noopener';
    }
    head.append(title, report);

    const progress = document.createElement('div');
    progress.className = 'progress-wrap';
    const progressCopy = document.createElement('div');
    progressCopy.className = 'progress-copy';
    progressCopy.append(node('span', '', task.currentStage), node('span', '', `${task.progress}%`));
    const track = document.createElement('div');
    track.className = 'progress-track';
    const fill = document.createElement('i');
    fill.style.width = `${task.progress}%`;
    track.append(fill);
    progress.append(progressCopy, track);

    const metrics = document.createElement('div');
    metrics.className = 'agent-metrics';
    metrics.append(metric('AGENT RUNS', task.agentRunCount, 'metric-agent-runs'),
        metric('MODEL CALLS', task.modelCallCount, 'metric-task-models'),
        metric('TOOL CALLS', task.toolCallCount, 'metric-task-tools'),
        metric('EVENTS', events.length, 'metric-event-count'));

    const investigation = document.createElement('div');
    investigation.className = 'investigation-grid';
    const console = document.createElement('section');
    console.className = 'live-console';
    const consoleBar = document.createElement('div');
    consoleBar.className = 'console-bar';
    const liveTitle = document.createElement('strong');
    liveTitle.append(node('i', '', ''), document.createTextNode('AGENT 实时调查链路'));
    consoleBar.append(liveTitle, node('span', '', '公开推理摘要 / 调用 / 工具 / 证据'));
    const feed = document.createElement('div');
    feed.id = 'event-feed';
    feed.className = 'event-feed';
    if (!events.length) feed.append(node('div', 'empty-state', '等待 Agent 事件…'));
    events.slice(-120).forEach(event => feed.append(eventRow(event, false)));
    console.append(consoleBar, feed);

    const roster = document.createElement('aside');
    roster.className = 'agent-roster';
    const rosterBar = document.createElement('div');
    rosterBar.className = 'console-bar';
    rosterBar.append(node('strong', '', 'AGENT 调用情况'), node('span', '', `${agents.length} RUNS`));
    const agentList = document.createElement('div');
    agentList.id = 'agent-list';
    agentList.className = 'agent-list';
    renderAgentList(agentList, agents);
    roster.append(rosterBar, agentList);
    investigation.append(console, roster);

    const findingSection = document.createElement('section');
    findingSection.className = 'finding-section';
    const findingHeading = document.createElement('div');
    findingHeading.className = 'finding-heading';
    findingHeading.append(node('h4', '', '确认漏洞'),
        node('span', '', `${findings.length} CONFIRMED FINDINGS`));
    const findingList = document.createElement('div');
    findingList.id = 'finding-list';
    renderFindingList(findingList, findings, task.status);
    findingSection.append(findingHeading, findingList);

    fragment.append(head, progress);
    if (task.errorMessage) fragment.append(node('p', 'error-message', task.errorMessage));
    fragment.append(metrics, investigation, findingSection);
    return fragment;
}

function metric(label, value, id) {
    const item = document.createElement('span');
    item.append(node('small', '', label), node('b', '', String(value)));
    item.querySelector('b').id = id;
    return item;
}

function updateDetailSummary(task) {
    if (state.renderedTaskId !== task.taskId) return;
    const progressCopy = elements.detail.querySelector('.progress-copy');
    const fill = elements.detail.querySelector('.progress-track i');
    if (progressCopy) {
        progressCopy.children[0].textContent = task.currentStage;
        progressCopy.children[1].textContent = `${task.progress}%`;
    }
    if (fill) fill.style.width = `${task.progress}%`;
    setText('#metric-agent-runs', task.agentRunCount);
    setText('#metric-task-models', task.modelCallCount);
    setText('#metric-task-tools', task.toolCallCount);
}

async function refreshFindings(task) {
    state.renderedFindingCount = task.findingCount;
    state.renderedStatus = task.status;
    if (task.findingCount <= 0 && task.status !== 'COMPLETED') return;
    try {
        const findings = await fetchJson(`/api/tasks/${task.taskId}/findings`);
        if (state.selectedTaskId !== task.taskId) return;
        const list = document.querySelector('#finding-list');
        if (list) renderFindingList(list, findings, task.status);
        const count = elements.detail.querySelector('.finding-heading span');
        if (count) count.textContent = `${findings.length} CONFIRMED FINDINGS`;
    } catch (ignored) {
        // 下一轮任务刷新会重试，不打断实时事件流。
    }
}

function renderFindingList(container, findings, status) {
    container.replaceChildren();
    if (!findings.length) {
        container.append(node('div', 'empty-state', status === 'COMPLETED'
            ? '本轮审计没有产生通过 Critic 证据门槛的问题。' : '专业 Agent 正在调查，确认结果将在此出现。'));
        return;
    }
    findings.forEach(finding => container.append(findingCard(finding)));
}

function findingCard(finding) {
    const details = document.createElement('details');
    details.className = 'finding-card';
    const summary = document.createElement('summary');
    summary.className = 'finding-summary';
    summary.append(node('i', `severity-dot ${finding.severity}`, ''), node('strong', '', finding.title),
        node('small', '', `${severityText(finding.severity)} / 可信度${confidenceText(finding.confidence)}`));
    const body = document.createElement('div');
    body.className = 'finding-body';
    body.append(node('p', '', `${finding.filePath}:${finding.startLine}${finding.endpoint ? ` · ${finding.endpoint}` : ''}`));
    appendFindingDescription(body, finding.description);
    body.append(node('pre', '', finding.evidence), node('p', '', `修复建议：${finding.remediation}`));
    details.append(summary, body);
    return details;
}

function appendFindingDescription(container, value) {
    const description = (value || '').trim();
    const marker = 'Critic Agent 复核：';
    const critic = description.indexOf(marker);
    if (critic < 0) {
        container.append(node('p', 'finding-description', description));
        return;
    }
    container.append(node('p', 'finding-description', description.slice(0, critic).trim()),
        node('p', 'critic-review', description.slice(critic).trim()));
}

function seedEvents(taskId, events) {
    const ids = new Set();
    events.forEach(event => ids.add(eventKey(event)));
    state.eventIdsByTask.set(taskId, ids);
    state.eventsByTask.set(taskId, [...events]);
}

function connectEventStream(taskId) {
    closeEventStream();
    setStreamState('connecting', '正在连接实时事件');
    const source = new EventSource(`/api/tasks/${taskId}/events/stream`);
    state.eventSource = source;
    source.addEventListener('connected', () => setStreamState('live', 'Agent 事件实时连接'));
    source.addEventListener('agent-event', event => {
        try {
            appendAgentEvent(taskId, JSON.parse(event.data));
        } catch (error) {
            setStreamState('error', '事件解析失败');
        }
    });
    source.onerror = () => setStreamState('error', '实时连接重试中');
}

function closeEventStream() {
    if (state.eventSource) state.eventSource.close();
    state.eventSource = null;
}

function appendAgentEvent(taskId, event) {
    const ids = state.eventIdsByTask.get(taskId) || new Set();
    const key = eventKey(event);
    if (ids.has(key)) return;
    ids.add(key);
    state.eventIdsByTask.set(taskId, ids);
    const events = state.eventsByTask.get(taskId) || [];
    events.push(event);
    if (events.length > 300) events.splice(0, events.length - 300);
    state.eventsByTask.set(taskId, events);
    if (state.selectedTaskId !== taskId || state.renderedTaskId !== taskId) return;

    const feed = document.querySelector('#event-feed');
    if (feed) {
        const nearBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 90;
        feed.querySelector('.empty-state')?.remove();
        feed.append(eventRow(event, true));
        while (feed.children.length > 120) feed.firstElementChild.remove();
        if (nearBottom) feed.scrollTop = feed.scrollHeight;
    }
    setText('#metric-event-count', events.length);
    if (['STARTED', 'COMPLETED', 'ERROR', 'FINDING', 'REJECTED'].includes(event.eventType)) {
        scheduleAgentRefresh(taskId);
    }
}

function eventRow(event, animate) {
    const row = document.createElement('article');
    row.className = `event-row ${String(event.eventType || '').toLowerCase()}`;
    if (!animate) row.style.animation = 'none';
    const meta = document.createElement('div');
    meta.className = 'event-meta';
    meta.append(node('b', '', agentText(event.agentType)),
        node('span', '', eventTypeText(event.eventType)));
    const time = document.createElement('time');
    time.textContent = event.createdAt ? new Intl.DateTimeFormat('zh-CN', {
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(new Date(event.createdAt)) : '刚刚';
    meta.append(time);
    const message = String(event.message || '');
    const copy = node('p', 'event-message', message.length > 1000 ? `${message.slice(0, 1000)}…` : message);
    row.append(meta, copy);
    if (message.length > 1000) {
        const expand = node('button', 'event-expand', '展开完整内容');
        expand.type = 'button';
        expand.addEventListener('click', () => {
            const expanded = expand.dataset.expanded === 'true';
            copy.textContent = expanded ? `${message.slice(0, 1000)}…` : message;
            expand.dataset.expanded = String(!expanded);
            expand.textContent = expanded ? '展开完整内容' : '收起内容';
        });
        row.append(expand);
    }
    return row;
}

function scheduleAgentRefresh(taskId) {
    clearTimeout(state.agentRefreshTimer);
    state.agentRefreshTimer = setTimeout(async () => {
        if (state.selectedTaskId !== taskId) return;
        try {
            const agents = await fetchJson(`/api/tasks/${taskId}/agents`);
            const list = document.querySelector('#agent-list');
            if (list) renderAgentList(list, agents);
        } catch (ignored) {
            // 实时事件仍可继续展示。
        }
    }, 250);
}

function renderAgentList(container, agents) {
    container.replaceChildren();
    if (!agents.length) {
        container.append(node('div', 'empty-state', '等待 Agent 启动…'));
        return;
    }
    [...agents].reverse().slice(0, 40).forEach(agent => {
        const item = document.createElement('article');
        item.className = 'agent-item';
        const heading = document.createElement('div');
        heading.append(node('strong', '', agentText(agent.agentType)),
            node('small', '', runStatusText(agent.status)));
        item.append(heading, node('p', '', agent.targetSymbol || agent.summary || '项目级任务'));
        container.append(item);
    });
}

function eventKey(event) {
    return event.id != null ? `id:${event.id}`
        : `${event.runId || ''}|${event.eventType || ''}|${event.createdAt || ''}|${event.message || ''}`;
}

function renderEmptyDetail() {
    state.renderedTaskId = null;
    closeEventStream();
    setStreamState('idle', '等待选择任务');
    elements.detail.replaceChildren(node('div', 'detail-empty', '暂无可展示的审计任务'));
}

function setStreamState(status, message) {
    elements.streamState.className = `stream-state ${status === 'live' ? '' : status}`;
    elements.streamState.querySelector('span').textContent = message;
}

function setText(selector, value) {
    const target = document.querySelector(selector);
    if (target) target.textContent = String(value);
}

function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text;
    return element;
}

function statusText(status) {
    return ({ UPLOADED: '排队', COMPLETED: '完成', FAILED: '失败', CANCELLED: '取消' })[status] || '运行中';
}

function runStatusText(status) {
    return ({ RUNNING: '运行中', COMPLETED: '已完成', FAILED: '失败' })[status] || status;
}

function agentText(agent) {
    return ({
        RECON: 'Recon Agent', ORCHESTRATOR: 'Orchestrator', SQL_INJECTION: 'SQL 注入 Agent',
        AUTHORIZATION: '权限审计 Agent', STORED_XSS: '存储 XSS Agent',
        VALIDATION_BYPASS: '验证绕过 Agent', FINANCIAL_RISK: '资金风险 Agent',
        CRITIC: 'Critic Agent', REPORT: 'Report Agent'
    })[agent] || agent || 'SYSTEM';
}

function eventTypeText(type) {
    return ({
        STARTED: '启动', MODEL_CALL: '模型调用', REASONING: '推理摘要', PLAN: '审计计划',
        TOOL_CALL: '工具调用', OBSERVATION: '工具观察', HYPOTHESIS: '漏洞假设',
        FINDING: '确认问题', REJECTED: '否决', COMPLETED: '完成', ERROR: '错误'
    })[type] || type;
}

function severityText(value) {
    return ({ CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危' })[value] || value;
}

function confidenceText(value) {
    return ({ HIGH: '高', MEDIUM: '中', LOW: '低' })[value] || value;
}

function formatTime(value) {
    return value ? new Intl.DateTimeFormat('zh-CN', {
        year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(new Date(value)) : '—';
}

function showMessage(message, error = false) {
    elements.message.textContent = message;
    elements.message.style.color = error ? '#ff8b70' : '#c9ff45';
}

document.querySelectorAll('.side-nav a').forEach(link => link.addEventListener('click', () => {
    document.querySelectorAll('.side-nav a').forEach(item => item.classList.remove('active'));
    link.classList.add('active');
}));

window.addEventListener('beforeunload', closeEventStream);
loadTasks();
state.poller = setInterval(loadTasks, 4000);
