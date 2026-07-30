const TERMINAL_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);
const ROUTES = new Set(['overview', 'new-audit', 'tasks', 'projects']);

const state = {
    route: 'overview',
    tasks: [],
    repositories: [],
    projects: [],
    commits: [],
    selectedTaskId: null,
    selectedProjectId: null,
    renderedTaskId: null,
    renderedTaskStatus: null,
    renderedFindingCount: -1,
    eventSource: null,
    eventKeys: new Map(),
    events: new Map(),
    loadingTasks: false,
    loadingProjects: false,
    agentRefreshTimer: null,
    poller: null
};

const ui = {
    sidebar: document.querySelector('#sidebar'),
    menuToggle: document.querySelector('#menu-toggle'),
    navLinks: [...document.querySelectorAll('[data-route]')],
    pages: [...document.querySelectorAll('[data-page]')],
    pageEyebrow: document.querySelector('#page-eyebrow'),
    pageTitle: document.querySelector('#page-title'),
    streamState: document.querySelector('#stream-state'),
    importForm: document.querySelector('#git-import-form'),
    projectName: document.querySelector('#project-name'),
    repositoryUrl: document.querySelector('#repository-url'),
    gitUsername: document.querySelector('#git-username'),
    gitToken: document.querySelector('#git-token'),
    importButton: document.querySelector('#import-button'),
    importMessage: document.querySelector('#git-message'),
    auditForm: document.querySelector('#audit-form'),
    repositorySelect: document.querySelector('#repository-select'),
    scanMode: document.querySelector('#scan-mode'),
    baseCommitGroup: document.querySelector('#base-commit-group'),
    baseCommit: document.querySelector('#base-commit'),
    targetCommit: document.querySelector('#target-commit'),
    refreshCommits: document.querySelector('#refresh-commits-button'),
    submitAudit: document.querySelector('#submit-button'),
    auditMessage: document.querySelector('#audit-message'),
    refreshTasks: document.querySelector('#refresh-button'),
    taskList: document.querySelector('#task-list'),
    taskCount: document.querySelector('#task-count'),
    taskDetail: document.querySelector('#task-detail'),
    recentTasks: document.querySelector('#recent-task-list'),
    metricTasks: document.querySelector('#metric-tasks'),
    metricActive: document.querySelector('#metric-active'),
    metricFindings: document.querySelector('#metric-findings'),
    metricModelCalls: document.querySelector('#metric-model-calls'),
    refreshProjects: document.querySelector('#refresh-projects-button'),
    includeArchived: document.querySelector('#include-archived-projects'),
    projectList: document.querySelector('#project-list'),
    projectCount: document.querySelector('#project-count'),
    projectDetail: document.querySelector('#project-detail'),
    toastRegion: document.querySelector('#toast-region'),
    confirmDialog: document.querySelector('#confirm-dialog'),
    dialogTitle: document.querySelector('#dialog-title'),
    dialogMessage: document.querySelector('#dialog-message'),
    dialogConfirm: document.querySelector('#dialog-confirm')
};

const PAGE_META = {
    overview: ['SECURITY POSTURE / LIVE', '态势总览'],
    'new-audit': ['NEW INVESTIGATION', '发起审计'],
    tasks: ['INVESTIGATION CENTER', '审计任务'],
    projects: ['PROJECT REGISTRY', '项目管理']
};

function bootstrap() {
    bindNavigation();
    bindForms();
    routeFromHash();
    Promise.allSettled([loadRepositories(), loadProjects(), loadTasks({ forceDetail: true })]);
    state.poller = window.setInterval(() => loadTasks(), 4000);
}

function bindNavigation() {
    window.addEventListener('hashchange', routeFromHash);
    window.addEventListener('beforeunload', closeEventStream);
    ui.menuToggle.addEventListener('click', () => {
        const open = ui.sidebar.classList.toggle('open');
        ui.menuToggle.setAttribute('aria-expanded', String(open));
    });
    ui.navLinks.forEach(link => link.addEventListener('click', () => closeMobileMenu()));
    document.addEventListener('click', event => {
        if (window.innerWidth > 820 || !ui.sidebar.classList.contains('open')) return;
        if (!ui.sidebar.contains(event.target) && !ui.menuToggle.contains(event.target)) closeMobileMenu();
    });
}

function bindForms() {
    ui.importForm.addEventListener('submit', importRepository);
    ui.auditForm.addEventListener('submit', submitAudit);
    ui.repositorySelect.addEventListener('change', loadCommits);
    ui.scanMode.addEventListener('change', updateScanMode);
    ui.refreshCommits.addEventListener('click', refreshCommits);
    ui.refreshTasks.addEventListener('click', () => loadTasks({ forceDetail: true, notify: true }));
    ui.refreshProjects.addEventListener('click', () => loadProjects(state.selectedProjectId, true));
    ui.includeArchived.addEventListener('change', () => loadProjects());
}

function routeFromHash() {
    const candidate = window.location.hash.replace(/^#\/?/, '').split('/')[0];
    const route = ROUTES.has(candidate) ? candidate : 'overview';
    if (!candidate || !ROUTES.has(candidate)) history.replaceState(null, '', '#/overview');
    state.route = route;
    ui.pages.forEach(page => {
        const active = page.dataset.page === route;
        page.hidden = !active;
        page.classList.toggle('entering', active);
    });
    ui.navLinks.forEach(link => {
        const active = link.dataset.route === route;
        link.classList.toggle('active', active);
        if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
    const [eyebrow, title] = PAGE_META[route];
    ui.pageEyebrow.textContent = eyebrow;
    ui.pageTitle.textContent = title;
    document.title = `${title} · DeepAudit`;
    window.scrollTo({ top: 0, behavior: 'auto' });
    closeMobileMenu();

    if (route === 'tasks') {
        const task = selectedTask();
        if (task) {
            if (state.renderedTaskId !== task.taskId) renderTaskDetail(task);
            else connectEventStream(task.taskId);
        }
    } else {
        closeEventStream();
        setConnection('idle', '等待选择任务');
    }
    if (route === 'projects' && state.selectedProjectId && !ui.projectDetail.dataset.projectId) {
        renderProjectDetail();
    }
}

function closeMobileMenu() {
    ui.sidebar.classList.remove('open');
    ui.menuToggle.setAttribute('aria-expanded', 'false');
}

async function importRepository(event) {
    event.preventDefault();
    ui.importButton.disabled = true;
    setFormMessage(ui.importMessage, '正在安全读取仓库与提交记录…');
    try {
        const payload = Object.fromEntries(new FormData(ui.importForm).entries());
        const response = await fetchJson('/api/projects/git', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        ui.gitToken.value = '';
        await Promise.all([
            loadRepositories(response.project.projectId),
            loadProjects(response.project.projectId)
        ]);
        populateCommits(response.commits);
        setFormMessage(ui.importMessage, response.message || '仓库已连接，可以配置扫描范围。');
        toast('仓库连接成功，提交记录已就绪。');
    } catch (error) {
        setFormMessage(ui.importMessage, error.message, true);
    } finally {
        ui.importButton.disabled = false;
    }
}

async function submitAudit(event) {
    event.preventDefault();
    const projectId = ui.repositorySelect.value;
    const incremental = ui.scanMode.value === 'INCREMENTAL';
    const baseCommit = incremental ? ui.baseCommit.value : null;
    const targetCommit = ui.targetCommit.value;
    if (!projectId || !targetCommit || (incremental && !baseCommit)) {
        setFormMessage(ui.auditMessage, '请选择仓库和完整的提交范围。', true);
        return;
    }
    if (incremental && baseCommit === targetCommit) {
        setFormMessage(ui.auditMessage, 'Base 与 Target 不能是同一个提交。', true);
        return;
    }
    ui.submitAudit.disabled = true;
    setFormMessage(ui.auditMessage, '正在创建审计任务…');
    try {
        const response = await fetchJson(`/api/projects/${projectId}/audits`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scanMode: ui.scanMode.value, baseCommit, targetCommit })
        });
        state.selectedTaskId = response.taskId;
        state.renderedTaskId = null;
        setFormMessage(ui.auditMessage, response.message || '审计任务已创建。');
        await loadTasks({ forceDetail: true });
        toast('审计已进入任务队列。');
        window.location.hash = '#/tasks';
    } catch (error) {
        setFormMessage(ui.auditMessage, error.message, true);
    } finally {
        ui.submitAudit.disabled = false;
    }
}

async function loadRepositories(selectedProjectId = null) {
    try {
        const repositories = await fetchJson('/api/projects');
        state.repositories = Array.isArray(repositories) ? repositories : [];
        const previous = selectedProjectId || ui.repositorySelect.value;
        ui.repositorySelect.replaceChildren(new Option('请选择仓库', ''));
        state.repositories.forEach(repository => {
            ui.repositorySelect.add(new Option(
                `${repository.name} · ${repository.defaultBranch || '默认分支未知'}`,
                repository.projectId
            ));
        });
        const selected = state.repositories.some(item => item.projectId === previous)
            ? previous : state.repositories[0]?.projectId;
        if (selected) {
            ui.repositorySelect.value = selected;
            await loadCommits();
        } else {
            populateCommits([]);
        }
    } catch (error) {
        setFormMessage(ui.auditMessage, `无法读取仓库：${error.message}`, true);
    }
}

async function loadCommits() {
    const projectId = ui.repositorySelect.value;
    if (!projectId) {
        populateCommits([]);
        return;
    }
    setFormMessage(ui.auditMessage, '正在读取提交记录…');
    try {
        const commits = await fetchJson(`/api/projects/${projectId}/commits?limit=200`);
        populateCommits(commits);
        setFormMessage(ui.auditMessage, commits.length ? `已读取 ${commits.length} 条提交记录。` : '仓库暂无提交记录。');
    } catch (error) {
        populateCommits([]);
        setFormMessage(ui.auditMessage, error.message, true);
    }
}

async function refreshCommits() {
    const projectId = ui.repositorySelect.value;
    if (!projectId) {
        setFormMessage(ui.auditMessage, '请先选择仓库。', true);
        return;
    }
    ui.refreshCommits.disabled = true;
    setFormMessage(ui.auditMessage, '正在从远端刷新提交记录…');
    try {
        const commits = await fetchJson(`/api/projects/${projectId}/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: ui.gitUsername.value, accessToken: ui.gitToken.value })
        });
        ui.gitToken.value = '';
        populateCommits(commits);
        setFormMessage(ui.auditMessage, `提交记录已刷新，共 ${commits.length} 条。`);
        toast('仓库提交记录已刷新。');
    } catch (error) {
        setFormMessage(ui.auditMessage, error.message, true);
    } finally {
        ui.refreshCommits.disabled = false;
    }
}

function populateCommits(commits) {
    state.commits = Array.isArray(commits) ? commits : [];
    ui.baseCommit.replaceChildren();
    ui.targetCommit.replaceChildren();
    if (!state.commits.length) {
        ui.baseCommit.add(new Option('暂无可用提交', ''));
        ui.targetCommit.add(new Option('暂无可用提交', ''));
    } else {
        state.commits.forEach(commit => {
            const branches = commit.branches?.length ? commit.branches.join(', ') : '无活动分支';
            const label = `${commit.shortSha || commit.sha?.slice(0, 8)} · ${commit.message || '无提交说明'} · ${branches} · ${formatTime(commit.committedAt)}`;
            ui.baseCommit.add(new Option(label, commit.sha));
            ui.targetCommit.add(new Option(label, commit.sha));
        });
        if (state.commits.length > 1) ui.baseCommit.selectedIndex = 1;
    }
    updateScanMode();
}

function updateScanMode() {
    const incremental = ui.scanMode.value === 'INCREMENTAL';
    ui.baseCommitGroup.hidden = !incremental;
    ui.baseCommit.required = incremental;
}

async function loadTasks({ forceDetail = false, notify = false } = {}) {
    if (state.loadingTasks) return;
    state.loadingTasks = true;
    try {
        const tasks = await fetchJson('/api/tasks');
        state.tasks = Array.isArray(tasks) ? tasks : [];
        if (!state.selectedTaskId && state.tasks.length) state.selectedTaskId = state.tasks[0].taskId;
        if (state.selectedTaskId && !state.tasks.some(task => task.taskId === state.selectedTaskId)) {
            state.selectedTaskId = state.tasks[0]?.taskId || null;
            state.renderedTaskId = null;
        }
        renderDashboard();
        renderTaskList();
        if (notify) toast('任务状态已刷新。');
        if (state.route !== 'tasks') return;
        const task = selectedTask();
        if (!task) {
            renderEmptyTaskDetail();
            return;
        }
        if (forceDetail || state.renderedTaskId !== task.taskId) {
            await renderTaskDetail(task);
            return;
        }
        const statusChanged = task.status !== state.renderedTaskStatus;
        const findingsChanged = task.findingCount !== state.renderedFindingCount;
        updateTaskSummary(task);
        if (findingsChanged || statusChanged) await refreshFindings(task);
        if (task.scanMode === 'INCREMENTAL' && statusChanged) await refreshMethodChanges(task);
        state.renderedTaskStatus = task.status;
    } catch (error) {
        ui.taskList.replaceChildren(emptyState(`无法读取任务：${error.message}`));
        if (notify) toast(error.message, true);
    } finally {
        state.loadingTasks = false;
    }
}

function renderDashboard() {
    const active = state.tasks.filter(task => !TERMINAL_STATUSES.has(task.status)).length;
    ui.metricTasks.textContent = String(state.tasks.length);
    ui.metricActive.textContent = String(active);
    ui.metricFindings.textContent = String(state.tasks.reduce((sum, task) => sum + Number(task.findingCount || 0), 0));
    ui.metricModelCalls.textContent = String(state.tasks.reduce((sum, task) => sum + Number(task.modelCallCount || 0), 0));
    ui.recentTasks.replaceChildren();
    if (!state.tasks.length) {
        ui.recentTasks.append(emptyState('暂无审计记录', true));
        return;
    }
    state.tasks.slice(0, 4).forEach(task => {
        const row = el('div', 'recent-row');
        row.tabIndex = 0;
        row.setAttribute('role', 'button');
        const copy = el('div');
        copy.append(el('strong', '', task.projectName),
            el('small', '', `${scanModeText(task.scanMode)} · ${task.currentStage || statusText(task.status)} · ${formatTime(task.createdAt)}`));
        row.append(copy, statusTag(task.status));
        const open = () => openTask(task.taskId);
        row.addEventListener('click', open);
        row.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); }
        });
        ui.recentTasks.append(row);
    });
}

function renderTaskList() {
    ui.taskCount.textContent = String(state.tasks.length);
    ui.taskList.replaceChildren();
    if (!state.tasks.length) {
        ui.taskList.append(emptyState('暂无审计任务'));
        return;
    }
    state.tasks.forEach((task, index) => {
        const button = el('button', `entity-button${task.taskId === state.selectedTaskId ? ' active' : ''}`);
        button.type = 'button';
        button.addEventListener('click', () => selectTask(task.taskId));
        const copy = el('span', 'entity-copy');
        const title = el('span', 'entity-title-row');
        title.append(el('strong', '', task.projectName), statusTag(task.status));
        copy.append(title,
            el('small', '', `${scanModeText(task.scanMode)} · ${task.currentStage || '等待启动'}`));
        if (!TERMINAL_STATUSES.has(task.status)) {
            const progress = el('span', 'entity-progress');
            const fill = el('i');
            fill.style.width = `${clampProgress(task.progress)}%`;
            progress.append(fill);
            copy.append(progress);
        } else {
            copy.append(el('small', '', `${task.findingCount || 0} 个确认问题 · ${formatTime(task.createdAt)}`));
        }
        button.append(el('span', 'entity-index', String(index + 1).padStart(2, '0')), copy);
        ui.taskList.append(button);
    });
}

function openTask(taskId) {
    state.selectedTaskId = taskId;
    state.renderedTaskId = null;
    if (state.route === 'tasks') selectTask(taskId); else window.location.hash = '#/tasks';
}

async function selectTask(taskId) {
    if (state.selectedTaskId === taskId && state.renderedTaskId === taskId) return;
    state.selectedTaskId = taskId;
    state.renderedTaskId = null;
    renderTaskList();
    const task = selectedTask();
    if (task) await renderTaskDetail(task);
}

function selectedTask() {
    return state.tasks.find(task => task.taskId === state.selectedTaskId);
}

async function renderTaskDetail(task) {
    const taskId = task.taskId;
    ui.taskDetail.removeAttribute('data-task-id');
    ui.taskDetail.replaceChildren(el('div', 'loading-block', '正在加载调查上下文…'));
    closeEventStream();
    try {
        const [findings, events, agents, methodChanges] = await Promise.all([
            task.findingCount > 0 || task.status === 'COMPLETED'
                ? fetchJson(`/api/tasks/${taskId}/findings`) : Promise.resolve([]),
            fetchJson(`/api/tasks/${taskId}/events`),
            fetchJson(`/api/tasks/${taskId}/agents`),
            task.scanMode === 'INCREMENTAL'
                ? fetchJson(`/api/tasks/${taskId}/method-changes`).catch(() => []) : Promise.resolve([])
        ]);
        if (state.selectedTaskId !== taskId) return;
        seedEvents(taskId, events);
        ui.taskDetail.replaceChildren(buildTaskDetail(task, findings, agents, events, methodChanges));
        ui.taskDetail.dataset.taskId = taskId;
        state.renderedTaskId = taskId;
        state.renderedTaskStatus = task.status;
        state.renderedFindingCount = task.findingCount;
        if (state.route === 'tasks') connectEventStream(taskId);
    } catch (error) {
        if (state.selectedTaskId !== taskId) return;
        ui.taskDetail.replaceChildren(emptyState(`无法读取任务详情：${error.message}`));
        setConnection('error', '任务详情加载失败');
    }
}

function buildTaskDetail(task, findings, agents, events, methodChanges) {
    const fragment = document.createDocumentFragment();
    const header = el('header', 'detail-header');
    const title = el('div', 'detail-header-copy');
    title.append(el('p', 'detail-kicker', `${scanModeText(task.scanMode).toUpperCase()} / ${statusText(task.status)}`),
        el('h3', '', task.projectName),
        el('p', 'detail-subtitle', `${commitRange(task)} · ${formatTime(task.createdAt)}`),
        el('p', 'detail-subtitle', task.changeSummary || task.repositoryUrl || '暂无变更摘要'));
    const actions = el('div', 'detail-actions');
    if (task.status === 'COMPLETED') {
        const report = el('a', 'button primary', '查看审计报告 ↗');
        report.href = `/api/tasks/${task.taskId}/report.html`;
        report.target = '_blank';
        report.rel = 'noopener';
        actions.append(report);
    } else {
        const waiting = el('button', 'button secondary', '报告生成中');
        waiting.disabled = true;
        actions.append(waiting);
    }
    header.append(title, actions);

    const body = el('div', 'detail-body');
    body.append(buildProgress(task));
    if (task.errorMessage) body.append(el('p', 'error-banner', task.errorMessage));
    body.append(buildTaskStats(task, events.length));
    if (task.scanMode === 'INCREMENTAL') body.append(buildMethodChanges(methodChanges));
    body.append(buildInvestigation(agents, events), buildFindings(findings, task.status));
    fragment.append(header, body);
    return fragment;
}

function buildProgress(task) {
    const section = el('section', 'progress-section');
    const label = el('div', 'progress-label');
    label.append(el('strong', '', task.currentStage || statusText(task.status)), el('span', '', `${clampProgress(task.progress)}%`));
    const track = el('div', 'progress-track');
    const fill = el('i');
    fill.style.width = `${clampProgress(task.progress)}%`;
    track.append(fill);
    section.append(label, track);
    return section;
}

function buildTaskStats(task, eventCount) {
    const stats = el('section', 'summary-stats');
    stats.append(summaryStat('AGENT RUNS', task.agentRunCount, 'task-agent-count'),
        summaryStat('MODEL CALLS', task.modelCallCount, 'task-model-count'),
        summaryStat('TOOL CALLS', task.toolCallCount, 'task-tool-count'),
        summaryStat('EVENTS', eventCount, 'task-event-count'));
    return stats;
}

function summaryStat(label, value, id) {
    const item = el('article');
    const number = el('strong', '', String(value ?? 0));
    number.id = id;
    item.append(el('small', '', label), number);
    return item;
}

function buildInvestigation(agents, events) {
    const section = el('section', 'detail-section');
    const heading = el('div', 'section-heading-row');
    heading.append(el('h4', '', 'Agent 调查链路'), el('span', '', '实时事件 / 工具调用 / 证据观察'));
    const grid = el('div', 'investigation-grid');

    const consolePanel = el('section', 'console-panel');
    const consoleHead = el('header', 'console-head');
    const liveTitle = el('strong');
    liveTitle.append(el('i', 'live-dot'), document.createTextNode(' 实时调查事件'));
    consoleHead.append(liveTitle, el('span', '', '最多显示最近 120 条'));
    const feed = el('div', 'event-feed');
    feed.id = 'event-feed';
    if (!events.length) feed.append(emptyState('等待 Agent 事件…', true));
    events.slice(-120).forEach(event => feed.append(buildEventRow(event, false)));
    consolePanel.append(consoleHead, feed);

    const rosterPanel = el('aside', 'console-panel');
    const rosterHead = el('header', 'console-head');
    rosterHead.append(el('strong', '', 'Agent 运行状态'), el('span', '', `${agents.length} RUNS`));
    const list = el('div', 'agent-list');
    list.id = 'agent-list';
    renderAgentList(list, agents);
    rosterPanel.append(rosterHead, list);
    grid.append(consolePanel, rosterPanel);
    section.append(heading, grid);
    return section;
}

function buildFindings(findings, status) {
    const section = el('section', 'detail-section');
    section.id = 'findings-section';
    const heading = el('div', 'section-heading-row');
    heading.append(el('h4', '', '确认漏洞'), el('span', 'finding-count', `${findings.length} CONFIRMED FINDINGS`));
    const list = el('div', 'finding-list');
    list.id = 'finding-list';
    renderFindingList(list, findings, status);
    section.append(heading, list);
    return section;
}

function renderFindingList(container, findings, status) {
    container.replaceChildren();
    if (!findings.length) {
        container.append(emptyState(status === 'COMPLETED'
            ? '本轮审计没有产生通过 Critic 证据门槛的问题。'
            : '专业 Agent 正在调查，确认结果将在此出现。', true));
        return;
    }
    findings.forEach(finding => container.append(buildFindingCard(finding)));
}

function buildFindingCard(finding) {
    const card = el('details', 'finding-card');
    const summary = el('summary');
    summary.append(el('i', `severity-mark ${finding.severity || ''}`));
    const title = el('span', 'finding-title');
    title.append(el('strong', '', finding.title || vulnerabilityTypeText(finding.type)),
        el('small', '', `${vulnerabilityTypeText(finding.type)} · ${deltaStatusText(finding.deltaStatus)}`));
    summary.append(title, el('span', 'finding-meta', `${severityText(finding.severity)} · 可信度${confidenceText(finding.confidence)}`));
    const body = el('div', 'finding-body');
    const location = `${finding.filePath || '未知文件'}:${finding.startLine || '?'}`
        + `${finding.endLine && finding.endLine !== finding.startLine ? `-${finding.endLine}` : ''}`;
    body.append(el('p', 'finding-location', `实际漏洞位置：${location}${finding.endpoint ? ` · ${finding.endpoint}` : ''}`));
    appendFindingDescription(body, finding.description);
    body.append(buildFindingEvidence(finding.evidence));
    if (finding.remediation) body.append(el('p', '', `修复建议：${finding.remediation}`));
    card.append(summary, body);
    return card;
}

function appendFindingDescription(container, value) {
    const description = String(value || '').trim();
    const marker = 'Critic Agent 复核：';
    const index = description.indexOf(marker);
    if (index < 0) {
        if (description) container.append(el('p', 'finding-description', description));
        return;
    }
    const main = description.slice(0, index).trim();
    if (main) container.append(el('p', 'finding-description', main));
    container.append(el('p', 'critic-review', description.slice(index).trim()));
}

function buildFindingEvidence(value) {
    const code = el('pre', 'finding-evidence');
    const lines = String(value || '暂无代码证据').split(/\r?\n/);
    lines.forEach(line => code.append(el('span', line.startsWith('>>> ') ? 'vulnerable-line' : '', line)));
    return code;
}

function buildMethodChanges(methodChanges) {
    const changes = Array.isArray(methodChanges) ? methodChanges : [];
    const groups = groupMethodChanges(changes);
    const section = el('section', 'detail-section');
    section.id = 'method-change-section';
    const panel = el('details', 'semantic-panel');
    panel.open = changes.some(change => change.changeKind === 'GUARD_REMOVED');
    const summary = el('summary');
    const title = el('span', 'semantic-title');
    title.append(el('small', '', 'INCREMENTAL SEMANTIC DIFF'), el('strong', '', '方法级语义变化'));
    const count = el('span', 'semantic-count');
    count.append(el('b', '', String(groups.length)), el('small', '', `${groups.length === 1 ? 'METHOD' : 'METHODS'} / ${changes.length} FACTS`));
    summary.append(title, count);
    const body = el('div', 'semantic-body');
    if (!changes.length) {
        body.append(emptyState('本次增量扫描未识别到 Java 方法级语义变化。', true));
    } else {
        const stats = el('div', 'change-stats');
        methodChangeKinds().forEach(kind => {
            const amount = changes.filter(change => change.changeKind === kind).length;
            if (!amount) return;
            const badge = el('span', `change-kind ${methodChangeTone(kind)}`);
            badge.append(el('b', '', String(amount)), document.createTextNode(methodChangeLabel(kind)));
            stats.append(badge);
        });
        const list = el('div', 'change-list');
        groups.forEach(group => list.append(buildMethodChangeCard(group)));
        body.append(stats, list);
    }
    panel.append(summary, body);
    section.append(panel);
    return section;
}

function groupMethodChanges(changes) {
    const grouped = new Map();
    changes.forEach(change => {
        const key = [change.basePath, change.targetPath, change.baseSymbol, change.targetSymbol, change.methodName]
            .map(value => value || '').join('|');
        if (!grouped.has(key)) grouped.set(key, { primary: change, changes: [] });
        grouped.get(key).changes.push(change);
    });
    return [...grouped.values()];
}

function buildMethodChangeCard(group) {
    const change = group.primary;
    const card = el('details', 'change-card');
    card.open = group.changes.some(item => item.changeKind === 'GUARD_REMOVED');
    const summary = el('summary');
    const title = el('span', 'change-title');
    title.append(el('strong', '', change.targetSymbol || change.baseSymbol || change.methodName || '未命名方法'),
        el('small', '', methodChangeLocation(change)));
    const badges = el('span', 'change-badges');
    [...new Set(group.changes.map(item => item.changeKind))].forEach(kind => {
        badges.append(el('span', `change-kind ${methodChangeTone(kind)}`, methodChangeLabel(kind)));
    });
    summary.append(title, badges);
    const body = el('div', 'change-body');
    const facts = el('ul', 'change-facts');
    group.changes.forEach(item => facts.append(el('li', '', item.details || methodChangeLabel(item.changeKind))));
    const compare = el('div', 'code-compare');
    compare.append(buildCodePane('BASE', change.basePath, change.baseStartLine, change.baseEndLine,
            change.baseContent, '基线提交中不存在该方法。'),
        buildCodePane('TARGET', change.targetPath, change.targetStartLine, change.targetEndLine,
            change.targetContent, '目标提交中已删除该方法。'));
    body.append(facts, compare);
    card.append(summary, body);
    return card;
}

function buildCodePane(label, path, startLine, endLine, content, fallback) {
    const pane = el('section', 'code-pane');
    const header = el('header');
    header.append(el('b', '', label), el('span', '', lineLocation(path, startLine, endLine)));
    const code = el('pre', content ? '' : 'empty', content || fallback);
    pane.append(header, code);
    return pane;
}

function updateTaskSummary(task) {
    if (state.renderedTaskId !== task.taskId) return;
    const progressLabel = ui.taskDetail.querySelector('.progress-label');
    const fill = ui.taskDetail.querySelector('.progress-track i');
    if (progressLabel) {
        progressLabel.children[0].textContent = task.currentStage || statusText(task.status);
        progressLabel.children[1].textContent = `${clampProgress(task.progress)}%`;
    }
    if (fill) fill.style.width = `${clampProgress(task.progress)}%`;
    setText('#task-agent-count', task.agentRunCount);
    setText('#task-model-count', task.modelCallCount);
    setText('#task-tool-count', task.toolCallCount);
}

async function refreshFindings(task) {
    state.renderedFindingCount = task.findingCount;
    try {
        if (task.findingCount <= 0 && task.status !== 'COMPLETED') return;
        const findings = await fetchJson(`/api/tasks/${task.taskId}/findings`);
        if (state.selectedTaskId !== task.taskId) return;
        const list = ui.taskDetail.querySelector('#finding-list');
        if (list) renderFindingList(list, findings, task.status);
        const count = ui.taskDetail.querySelector('.finding-count');
        if (count) count.textContent = `${findings.length} CONFIRMED FINDINGS`;
    } catch (_) {
        // Polling will retry without interrupting the event stream.
    }
}

async function refreshMethodChanges(task) {
    try {
        const changes = await fetchJson(`/api/tasks/${task.taskId}/method-changes`);
        if (state.selectedTaskId !== task.taskId) return;
        const current = ui.taskDetail.querySelector('#method-change-section');
        if (current) current.replaceWith(buildMethodChanges(changes));
    } catch (_) {
        // Method changes are supporting context; live investigation remains available.
    }
}

function seedEvents(taskId, events) {
    const list = Array.isArray(events) ? [...events] : [];
    state.events.set(taskId, list);
    state.eventKeys.set(taskId, new Set(list.map(eventKey)));
}

function connectEventStream(taskId) {
    if (state.eventSource?.datasetTaskId === taskId) return;
    closeEventStream();
    setConnection('connecting', '正在连接实时事件');
    const source = new EventSource(`/api/tasks/${taskId}/events/stream`);
    source.datasetTaskId = taskId;
    state.eventSource = source;
    source.addEventListener('connected', () => setConnection('live', 'Agent 事件实时连接'));
    source.addEventListener('agent-event', event => {
        try {
            appendAgentEvent(taskId, JSON.parse(event.data));
        } catch (_) {
            setConnection('error', '事件解析失败');
        }
    });
    source.onerror = () => setConnection('error', '实时连接重试中');
}

function closeEventStream() {
    if (state.eventSource) state.eventSource.close();
    state.eventSource = null;
}

function appendAgentEvent(taskId, event) {
    const keys = state.eventKeys.get(taskId) || new Set();
    const key = eventKey(event);
    if (keys.has(key)) return;
    keys.add(key);
    state.eventKeys.set(taskId, keys);
    const events = state.events.get(taskId) || [];
    events.push(event);
    if (events.length > 300) events.splice(0, events.length - 300);
    state.events.set(taskId, events);
    if (state.route !== 'tasks' || state.selectedTaskId !== taskId || state.renderedTaskId !== taskId) return;

    const feed = ui.taskDetail.querySelector('#event-feed');
    if (feed) {
        const nearBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 90;
        feed.querySelector('.empty-state')?.remove();
        feed.append(buildEventRow(event, true));
        while (feed.children.length > 120) feed.firstElementChild.remove();
        if (nearBottom) feed.scrollTop = feed.scrollHeight;
    }
    setText('#task-event-count', events.length);
    if (['STARTED', 'COMPLETED', 'ERROR', 'FINDING', 'REJECTED'].includes(event.eventType)) {
        scheduleAgentRefresh(taskId);
    }
}

function buildEventRow(event, animate) {
    const row = el('article', `event-card ${String(event.eventType || '').toLowerCase()}`);
    if (!animate) row.style.animation = 'none';
    const meta = el('div', 'event-meta');
    meta.append(el('strong', '', agentText(event.agentType)), el('span', '', eventTypeText(event.eventType)));
    const time = el('time', '', event.createdAt ? new Intl.DateTimeFormat('zh-CN', {
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(new Date(event.createdAt)) : '刚刚');
    meta.append(time);
    const toolCall = event.eventType === 'TOOL_CALL';
    const observation = event.eventType === 'OBSERVATION';
    const message = toolCall ? summarizeToolCall(event.message)
        : observation ? summarizeObservation(event.message)
            : String(event.message || '');
    const copy = el('p', 'event-message', message.length > 1000 ? `${message.slice(0, 1000)}…` : message);
    row.append(meta, copy);
    if (!toolCall && !observation && message.length > 1000) {
        const expand = el('button', 'event-expand', '展开完整内容');
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
    window.clearTimeout(state.agentRefreshTimer);
    state.agentRefreshTimer = window.setTimeout(async () => {
        if (state.selectedTaskId !== taskId) return;
        try {
            const agents = await fetchJson(`/api/tasks/${taskId}/agents`);
            const list = ui.taskDetail.querySelector('#agent-list');
            if (list) renderAgentList(list, agents);
        } catch (_) {
            // SSE continues even if the roster refresh fails.
        }
    }, 250);
}

function renderAgentList(container, agents) {
    container.replaceChildren();
    if (!agents.length) {
        container.append(emptyState('等待 Agent 启动…', true));
        return;
    }
    [...agents].reverse().slice(0, 40).forEach(agent => {
        const card = el('article', 'agent-card');
        const head = el('div');
        head.append(el('strong', '', agentText(agent.agentType)), el('small', '', runStatusText(agent.status)));
        card.append(head, el('p', '', agent.targetSymbol || agent.summary || '项目级任务'));
        container.append(card);
    });
}

function renderEmptyTaskDetail() {
    state.renderedTaskId = null;
    closeEventStream();
    setConnection('idle', '等待选择任务');
    const blank = el('div', 'blank-detail');
    blank.append(el('span', '', '⌁'), el('h3', '', '暂无可展示的审计任务'), el('p', '', '连接仓库并发起一次审计后，调查过程会在这里实时出现。'));
    ui.taskDetail.replaceChildren(blank);
}

async function loadProjects(selectedProjectId = null, notify = false) {
    if (state.loadingProjects) return;
    state.loadingProjects = true;
    try {
        const includeArchived = ui.includeArchived.checked;
        const projects = await fetchJson(`/api/projects?includeArchived=${includeArchived}`);
        state.projects = Array.isArray(projects) ? projects : [];
        const requested = selectedProjectId || state.selectedProjectId;
        state.selectedProjectId = state.projects.some(project => project.projectId === requested)
            ? requested : state.projects[0]?.projectId || null;
        renderProjectList();
        if (state.selectedProjectId) await renderProjectDetail(); else renderEmptyProjectDetail();
        if (notify) toast('项目列表已刷新。');
    } catch (error) {
        ui.projectList.replaceChildren(emptyState(`无法读取项目：${error.message}`));
        if (notify) toast(error.message, true);
    } finally {
        state.loadingProjects = false;
    }
}

function renderProjectList() {
    ui.projectCount.textContent = String(state.projects.length);
    ui.projectList.replaceChildren();
    if (!state.projects.length) {
        ui.projectList.append(emptyState('暂无扫描项目'));
        return;
    }
    state.projects.forEach((project, index) => {
        const button = el('button', `entity-button${project.projectId === state.selectedProjectId ? ' active' : ''}${project.archived ? ' archived' : ''}`);
        button.type = 'button';
        button.addEventListener('click', () => selectProject(project.projectId));
        const copy = el('span', 'entity-copy');
        const title = el('span', 'entity-title-row');
        title.append(el('strong', '', project.name), statusTag(project.archived ? 'ARCHIVED' : 'ACTIVE'));
        copy.append(title, el('small', '', project.defaultBranch || '默认分支未知'),
            el('small', '', project.repositoryUrl));
        button.append(el('span', 'entity-index', String(index + 1).padStart(2, '0')), copy);
        ui.projectList.append(button);
    });
}

async function selectProject(projectId) {
    if (state.selectedProjectId === projectId && ui.projectDetail.dataset.projectId === projectId) return;
    state.selectedProjectId = projectId;
    renderProjectList();
    await renderProjectDetail();
}

async function renderProjectDetail() {
    const project = state.projects.find(item => item.projectId === state.selectedProjectId);
    if (!project) {
        renderEmptyProjectDetail();
        return;
    }
    const projectId = project.projectId;
    ui.projectDetail.removeAttribute('data-project-id');
    ui.projectDetail.replaceChildren(el('div', 'loading-block', '正在加载项目与扫描历史…'));
    try {
        const audits = await fetchJson(`/api/projects/${projectId}/audits`);
        if (state.selectedProjectId !== projectId) return;
        ui.projectDetail.replaceChildren(buildProjectDetail(project, audits));
        ui.projectDetail.dataset.projectId = projectId;
    } catch (error) {
        ui.projectDetail.replaceChildren(emptyState(`无法读取项目详情：${error.message}`));
    }
}

function buildProjectDetail(project, audits) {
    const fragment = document.createDocumentFragment();
    const summary = el('header', 'project-summary');
    const copy = el('div');
    copy.append(el('p', 'detail-kicker', project.archived ? 'ARCHIVED PROJECT' : 'ACTIVE PROJECT'),
        el('h3', '', project.name), el('p', 'project-repo', project.repositoryUrl));
    summary.append(copy, statusTag(project.archived ? 'ARCHIVED' : 'ACTIVE'));

    const metadata = el('section', 'project-meta');
    metadata.append(projectMeta('DEFAULT BRANCH', project.defaultBranch || '—'),
        projectMeta('CREATED', formatTime(project.createdAt)),
        projectMeta('UPDATED', formatTime(project.updatedAt)),
        projectMeta('AUDIT HISTORY', String(audits.length)));

    const content = el('div', 'project-content');
    const editForm = el('form', 'project-edit-form');
    const nameField = projectField('项目名称', 'input');
    nameField.control.name = 'name';
    nameField.control.maxLength = 200;
    nameField.control.required = true;
    nameField.control.value = project.name;
    const descriptionField = projectField('项目描述', 'textarea');
    descriptionField.control.name = 'description';
    descriptionField.control.maxLength = 1000;
    descriptionField.control.placeholder = '记录项目用途或扫描范围（可选）';
    descriptionField.control.value = project.description || '';
    const save = el('button', 'button primary', '保存信息');
    save.type = 'submit';
    const message = el('p', 'project-message');
    editForm.append(nameField.wrapper, descriptionField.wrapper, save, message);
    editForm.addEventListener('submit', event => saveProject(event, project.projectId, save, message));

    const history = el('section', 'history-section');
    const historyHead = el('div', 'section-heading-row');
    historyHead.append(el('h4', '', '扫描历史'), el('span', '', `${audits.length} AUDITS`));
    const historyList = el('div', 'history-list');
    if (!audits.length) historyList.append(emptyState('该项目还没有扫描记录。', true));
    else audits.forEach(audit => historyList.append(buildHistoryRow(audit)));
    history.append(historyHead, historyList);

    const lifecycle = el('section', 'lifecycle-panel');
    const lifecycleCopy = el('div');
    lifecycleCopy.append(el('h4', '', project.archived ? '恢复与数据清理' : '项目归档'),
        el('p', '', project.archived
            ? '恢复后可以继续刷新仓库和发起审计；清理会删除扫描派生数据，但保留项目和裸 Git 仓库。'
            : '归档后将拒绝仓库刷新和新审计，已有扫描记录与报告仍可查看。'));
    const actions = el('div', 'lifecycle-actions');
    const archive = el('button', `button ${project.archived ? 'secondary' : 'warning'}`, project.archived ? '恢复项目' : '归档项目');
    archive.type = 'button';
    archive.addEventListener('click', () => toggleProjectArchive(project, archive));
    actions.append(archive);
    if (project.archived) {
        const cleanup = el('button', 'button danger', '清空扫描数据');
        cleanup.type = 'button';
        cleanup.disabled = audits.length === 0;
        cleanup.addEventListener('click', () => cleanupProject(project, cleanup));
        actions.append(cleanup);
    }
    lifecycle.append(lifecycleCopy, actions);
    content.append(editForm, history, lifecycle);
    fragment.append(summary, metadata, content);
    return fragment;
}

function projectMeta(label, value) {
    const item = el('article');
    item.append(el('small', '', label), el('strong', '', value));
    return item;
}

function projectField(label, type) {
    const wrapper = el('label', 'project-field');
    const control = document.createElement(type);
    wrapper.append(el('span', '', label), control);
    return { wrapper, control };
}

function buildHistoryRow(audit) {
    const row = el('button', 'history-row');
    row.type = 'button';
    row.addEventListener('click', () => openTask(audit.taskId));
    const copy = el('span');
    copy.append(el('strong', '', `${scanModeText(audit.scanMode)} · ${commitRange(audit)}`),
        el('small', '', `${formatTime(audit.createdAt)} · ${audit.findingCount || 0} 个确认问题`));
    row.append(copy, statusTag(audit.status));
    return row;
}

async function saveProject(event, projectId, button, message) {
    event.preventDefault();
    button.disabled = true;
    message.classList.remove('error');
    message.textContent = '正在保存…';
    try {
        const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
        await fetchJson(`/api/projects/${projectId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        message.textContent = '项目基本信息已保存。';
        await Promise.all([loadRepositories(projectId), loadProjects(projectId)]);
        toast('项目基本信息已保存。');
    } catch (error) {
        message.textContent = error.message;
        message.classList.add('error');
    } finally {
        button.disabled = false;
    }
}

async function toggleProjectArchive(project, button) {
    const action = project.archived ? '恢复' : '归档';
    const confirmed = await confirmAction({
        title: `${action}项目`,
        message: project.archived
            ? `恢复“${project.name}”后，可以继续刷新仓库和发起审计。`
            : `归档“${project.name}”后，将停止仓库刷新和新审计，但现有报告仍保留。`,
        confirmLabel: `${action}项目`,
        danger: !project.archived
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
        await fetchJson(`/api/projects/${project.projectId}/${project.archived ? 'restore' : 'archive'}`, { method: 'POST' });
        if (!project.archived) ui.includeArchived.checked = true;
        await Promise.all([loadRepositories(), loadProjects(project.projectId)]);
        toast(`项目已${action}。`);
    } catch (error) {
        toast(error.message, true);
        button.disabled = false;
    }
}

async function cleanupProject(project, button) {
    const confirmed = await confirmAction({
        title: '清空扫描数据',
        message: `将永久删除“${project.name}”的全部扫描任务、代码块、向量、漏洞和报告。项目记录与裸 Git 仓库仍会保留，此操作不可撤销。`,
        confirmLabel: '确认清空',
        danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
        const result = await fetchJson(`/api/projects/${project.projectId}/cleanup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirmation: 'DELETE_SCAN_DATA' })
        });
        state.selectedTaskId = null;
        state.renderedTaskId = null;
        await Promise.all([loadTasks({ forceDetail: true }), loadProjects(project.projectId)]);
        toast(`${result.message || '扫描数据已清理'}，共删除 ${result.deletedTaskCount || 0} 个任务。`);
    } catch (error) {
        toast(error.message, true);
        button.disabled = false;
    }
}

function renderEmptyProjectDetail() {
    ui.projectDetail.removeAttribute('data-project-id');
    const blank = el('div', 'blank-detail');
    blank.append(el('span', '', '⌂'), el('h3', '', '暂无可管理的扫描项目'), el('p', '', '连接一个 Git 仓库后，可以在这里维护信息和查看扫描历史。'));
    ui.projectDetail.replaceChildren(blank);
}

function confirmAction({ title, message, confirmLabel, danger = false }) {
    if (!ui.confirmDialog.showModal) return Promise.resolve(window.confirm(message));
    ui.dialogTitle.textContent = title;
    ui.dialogMessage.textContent = message;
    ui.dialogConfirm.textContent = confirmLabel;
    ui.dialogConfirm.className = `button ${danger ? 'danger' : 'primary'}`;
    ui.confirmDialog.showModal();
    return new Promise(resolve => {
        ui.confirmDialog.addEventListener('close', () => resolve(ui.confirmDialog.returnValue === 'confirm'), { once: true });
    });
}

async function fetchJson(url, options) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || `请求失败 (${response.status})`);
    return data;
}

function setFormMessage(element, message, error = false) {
    element.textContent = message || '';
    element.classList.toggle('error', error);
}

function setConnection(status, message) {
    ui.streamState.className = `connection-state ${status}`;
    ui.streamState.querySelector('span').textContent = message;
}

function toast(message, error = false) {
    const item = el('div', `toast${error ? ' error' : ''}`, message);
    ui.toastRegion.append(item);
    window.setTimeout(() => item.remove(), 4200);
}

function emptyState(message, compact = false) {
    return el('div', `empty-state${compact ? ' compact' : ''}`, message);
}

function statusTag(status) {
    const normalized = String(status || '').toLowerCase();
    return el('span', `status-tag ${normalized}`, statusText(status));
}

function el(tag, className = '', text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
}

function setText(selector, value) {
    const target = ui.taskDetail.querySelector(selector) || document.querySelector(selector);
    if (target) target.textContent = String(value ?? 0);
}

function clampProgress(value) {
    const number = Number(value || 0);
    return Math.min(100, Math.max(0, number));
}

function statusText(status) {
    return ({
        UPLOADED: '排队中', PENDING: '排队中', RUNNING: '运行中', COMPLETED: '已完成',
        FAILED: '失败', CANCELLED: '已取消', ACTIVE: '使用中', ARCHIVED: '已归档'
    })[status] || '运行中';
}

function scanModeText(mode) {
    return mode === 'INCREMENTAL' ? '增量扫描' : '全量扫描';
}

function runStatusText(status) {
    return ({ RUNNING: '运行中', COMPLETED: '已完成', FAILED: '失败' })[status] || status || '未知';
}

function agentText(agent) {
    return ({
        RECON: 'Recon Agent', ORCHESTRATOR: 'Triage Orchestrator', SQL_INJECTION: 'SQL 注入 Agent',
        AUTHORIZATION: '权限审计 Agent', UNAUTHORIZED_DISCLOSURE: '数据披露 Agent',
        STORED_XSS: '存储 XSS Agent', VALIDATION_BYPASS: '验证绕过 Agent',
        FINANCIAL_RISK: '金融风险 Agent', SECURITY_CONFIG: '安全配置 Agent',
        CRITIC: 'Critic Agent', REPORT: 'Report Agent'
    })[agent] || agent || 'SYSTEM';
}

function eventTypeText(type) {
    return ({
        STARTED: '启动', MODEL_CALL: '模型调用', REASONING: '推理摘要', PLAN: '审计计划',
        TOOL_CALL: '工具调用', OBSERVATION: '工具观察', HYPOTHESIS: '漏洞假设',
        FINDING: '确认问题', REJECTED: '否决', COMPLETED: '完成', ERROR: '错误'
    })[type] || type || '事件';
}

function severityText(value) {
    return ({ CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危' })[value] || value || '未知';
}

function confidenceText(value) {
    return ({ HIGH: '高', MEDIUM: '中', LOW: '低' })[value] || value || '未知';
}

function vulnerabilityTypeText(value) {
    return ({
        SQL_INJECTION: 'SQL 注入', AUTHORIZATION: '越权漏洞', UNAUTHORIZED_DISCLOSURE: '未授权数据披露',
        STORED_XSS: '存储型 XSS', VALIDATION_BYPASS: '验证绕过', FINANCIAL_RISK: '金融业务风险',
        SECURITY_CONFIG: '安全配置风险'
    })[value] || value || '安全问题';
}

function deltaStatusText(value) {
    return ({
        BASELINE: '全量基线', NEW: '变更新增', REGRESSED: '安全回归',
        PERSISTING: '持续存在', AFFECTED: '变更影响'
    })[value] || '未分类';
}

function methodChangeKinds() {
    return ['GUARD_REMOVED', 'GUARD_ADDED', 'SIGNATURE_CHANGED', 'METHOD_ADDED', 'METHOD_MODIFIED', 'METHOD_DELETED'];
}

function methodChangeLabel(kind) {
    return ({
        METHOD_ADDED: '方法新增', METHOD_MODIFIED: '方法修改', METHOD_DELETED: '方法删除',
        SIGNATURE_CHANGED: '签名变化', GUARD_ADDED: '防护新增', GUARD_REMOVED: '防护删除'
    })[kind] || kind || '未知变化';
}

function methodChangeTone(kind) {
    if (kind === 'GUARD_REMOVED' || kind === 'METHOD_DELETED') return 'danger';
    if (kind === 'GUARD_ADDED') return 'safe';
    if (kind === 'SIGNATURE_CHANGED') return 'attention';
    return 'neutral';
}

function methodChangeLocation(change) {
    return lineLocation(change.targetPath || change.basePath,
        change.targetStartLine ?? change.baseStartLine,
        change.targetEndLine ?? change.baseEndLine);
}

function lineLocation(path, startLine, endLine) {
    const file = path || '未知文件';
    if (startLine == null) return file;
    return `${file}:${startLine}${endLine != null && endLine !== startLine ? `-${endLine}` : ''}`;
}

function commitRange(audit) {
    const target = audit.targetCommit?.slice(0, 8) || '—';
    if (!audit.baseCommit) return target;
    const selectedBase = audit.baseCommit.slice(0, 8);
    const mergeBase = audit.mergeBase?.slice(0, 8);
    if (mergeBase && mergeBase !== selectedBase) return `${selectedBase}（共同祖先 ${mergeBase}） → ${target}`;
    return `${selectedBase} → ${target}`;
}

function formatTime(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return new Intl.DateTimeFormat('zh-CN', {
        year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(date);
}

function eventKey(event) {
    return event.id != null ? `id:${event.id}`
        : `${event.runId || ''}|${event.eventType || ''}|${event.createdAt || ''}|${event.message || ''}`;
}

function summarizeToolCall(message) {
    const raw = String(message || '').trim();
    const separator = raw.search(/[：:]/);
    const tool = (separator >= 0 ? raw.slice(0, separator) : raw).trim().toLowerCase();
    const summaries = {
        get_chunk: '读取目标代码块，核对实现细节',
        verify_relation: '验证候选代码与当前审计目标的确定性关系',
        call_context: '查询当前审计目标的直接调用上下文',
        get_call_chain: '追踪当前审计目标的调用链',
        trace_data_flow: '追踪输入到敏感操作的数据流',
        find_security_guards: '查找调用路径上的认证、授权与校验保护',
        search_symbols: '按符号、注解、路径或文本查找相关代码',
        explore_call_graph: '按方向和深度探索调用路径',
        get_change_context: '读取当前目标的 Base/Target 变更上下文',
        resolve_data_access: '解析关联的数据访问、SQL 与参数绑定',
        inspect_security_policy: '检查适用于当前入口的安全策略',
        trace_value: '定向追踪变量、数据来源与危险终点'
    };
    if (summaries[tool]) return `${tool}：${summaries[tool]}`;
    if (tool && /^[a-z0-9_-]{1,48}$/.test(tool)) return `${tool}：调用只读工具补充审计证据`;
    return '调用只读工具补充当前审计目标的相关证据';
}

function summarizeObservation(message) {
    const raw = String(message || '').trim();
    const chunkCount = (raw.match(/\bCHUNK_ID=\d+/g) || []).length;
    const pathCount = (raw.match(/^PATH\s+depth=/gm) || []).length;
    const changeCount = (raw.match(/^\[(?:METHOD_CHANGE|FILE_CHANGE)\]/gm) || []).length;

    if (!raw) return '工具观察已完成，本次未返回可展示的补充信息。';
    if (raw.includes('[TOOL_UNAVAILABLE]')) return '当前运行环境未提供本次调查所需的高级只读工具。';
    if (raw.includes('[RELATION_REJECTED]')) {
        return '候选代码与当前审计目标的关系未通过验证，不能作为漏洞证据。';
    }
    if (raw.includes('[VERIFIED_EVIDENCE]') || raw.includes('[VERIFIED_POLICY_RELATION]')) {
        return '已验证相关代码与当前审计目标存在确定性关系，可作为后续分析证据。';
    }
    if (raw.includes('[SEARCH_RESULT]')) {
        if (raw.includes('没有找到')) return '未检索到满足当前条件的相关代码符号。';
        return chunkCount > 0
            ? `已检索相关代码符号，获得 ${chunkCount} 个候选代码块供后续关系验证。`
            : '已完成相关代码符号检索，并将候选结果用于后续关系验证。';
    }
    if (raw.includes('[CALL_GRAPH]')) {
        if (raw.includes('没有找到')) return '已检查当前目标的调用图，未发现满足条件的可信调用路径。';
        return pathCount > 0
            ? `已分析当前目标的调用图，获得 ${pathCount} 条可信调用路径。`
            : '已分析当前目标的调用图并补充可信调用关系。';
    }
    if (raw.includes('[CHANGE_CONTEXT]')) {
        if (raw.includes('没有方法级或文件级')) return '已检查变更上下文，当前目标没有方法级或文件级增量记录。';
        return changeCount > 0
            ? `已读取 Base/Target 变更上下文，获得 ${changeCount} 项方法或文件变更。`
            : '已读取当前目标的 Base/Target 变更上下文。';
    }
    if (raw.includes('[DATA_ACCESS_ANALYSIS]') || raw.includes('[DATA_ACCESS]')) {
        if (raw.includes('未找到')) return '已检查相关数据访问代码，未发现满足当前条件的实现。';
        return '已定位相关数据访问实现，并提取参数绑定与动态 SQL 等语法指标。';
    }
    if (raw.includes('[SECURITY_POLICY]')) {
        if (raw.includes('未发现')) return '已检查当前入口的安全策略，未发现明确适用的认证或授权配置。';
        return '已检查当前入口适用的认证、授权与安全配置。';
    }
    if (raw.includes('[VALUE_TRACE]')) {
        if (raw.includes('没有找到')) return '已追踪相关变量，未发现满足条件的已解析数据流或参数映射。';
        return '已追踪相关变量从输入到敏感操作的数据流与参数映射。';
    }
    if (raw.includes('[SEMANTIC_EVIDENCE]')) {
        return '已查询确定性语义关系，补充调用链、数据流或安全防护证据。';
    }
    if (raw.includes('[UNVERIFIED_CANDIDATE]')) {
        return '已读取相关候选代码，仍需验证其与当前审计目标的确定性关系。';
    }
    if (/\bCHUNK_ID=\d+/.test(raw)) return '已读取目标代码块，供当前安全判断使用。';
    if (raw.includes('不能作为漏洞证据') || raw.includes('证据引用')) {
        return '已校验证据引用，当前提交内容尚未满足漏洞证据要求。';
    }
    return '已完成本次工具观察，并将结果用于下一步安全判断。';
}

bootstrap();
