const TERMINAL_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);
const ROUTES = new Set(['overview', 'new-audit', 'tasks', 'projects']);
const COMMITS_PER_BRANCH_LIMIT = 50;

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
    submittingAudit: false,
    taskRequestSequence: 0,
    loadingProjects: false,
    cancellingTaskIds: new Set(),
    agentRefreshTimer: null
};

const ui = {
    sidebar: document.querySelector('#sidebar'),
    menuToggle: document.querySelector('#menu-toggle'),
    navLinks: [...document.querySelectorAll('[data-route]')],
    pages: [...document.querySelectorAll('[data-page]')],
    importForm: document.querySelector('#git-import-form'),
    gitUsername: document.querySelector('#git-username'),
    gitToken: document.querySelector('#git-token'),
    importButton: document.querySelector('#import-button'),
    importMessage: document.querySelector('#git-message'),
    auditForm: document.querySelector('#audit-form'),
    repositorySelect: document.querySelector('#repository-select'),
    baseBranch: document.querySelector('#base-branch'),
    baseCommit: document.querySelector('#base-commit'),
    baseCommitHint: document.querySelector('#base-commit-hint'),
    targetBranch: document.querySelector('#target-branch'),
    targetCommit: document.querySelector('#target-commit'),
    targetCommitHint: document.querySelector('#target-commit-hint'),
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

const PAGE_TITLES = {
    overview: '态势总览',
    'new-audit': '发起审计',
    tasks: '审计任务',
    projects: '项目管理'
};

function bootstrap() {
    bindNavigation();
    bindForms();
    routeFromHash();
    Promise.allSettled([loadRepositories(), loadProjects(), loadTasks({ forceDetail: true })]);
    window.setInterval(() => loadTasks(), 4000);
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
    ui.baseBranch.addEventListener('change', () => populateBranchCommits('base'));
    ui.targetBranch.addEventListener('change', () => populateBranchCommits('target'));
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
    document.title = `${PAGE_TITLES[route]} · DeepAudit`;
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
    const baseCommit = ui.baseCommit.value;
    const targetCommit = ui.targetCommit.value;
    if (!projectId || !targetCommit || !baseCommit) {
        setFormMessage(ui.auditMessage, '请选择仓库和完整的提交范围。', true);
        return;
    }
    if (baseCommit === targetCommit) {
        setFormMessage(ui.auditMessage, 'Base 与 Target 不能是同一个提交。', true);
        return;
    }
    ui.submitAudit.disabled = true;
    state.submittingAudit = true;
    state.taskRequestSequence += 1;
    state.loadingTasks = false;
    setFormMessage(ui.auditMessage, '正在创建审计任务…');
    const previousTaskId = state.selectedTaskId;
    state.selectedTaskId = null;
    state.renderedTaskId = null;
    closeEventStream();
    window.location.hash = '#/tasks';
    ui.taskDetail.replaceChildren(el('div', 'loading-block', '正在创建审计任务并加入队列…'));
    try {
        const response = await fetchJson(`/api/projects/${projectId}/audits`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ baseCommit, targetCommit })
        });
        const task = queuedTaskFromSubmission(response);
        state.tasks = [task, ...state.tasks.filter(item => item.taskId !== task.taskId)];
        state.selectedTaskId = task.taskId;
        renderDashboard();
        renderTaskList();
        renderQueuedTask(task);
        setFormMessage(ui.auditMessage, response.message || '审计任务已创建。');
        toast('审计已进入任务队列。');
        void loadTasks({ forceDetail: true });
    } catch (error) {
        state.selectedTaskId = previousTaskId;
        state.renderedTaskId = null;
        window.location.hash = '#/new-audit';
        setFormMessage(ui.auditMessage, error.message, true);
        toast(error.message, true);
    } finally {
        state.submittingAudit = false;
        ui.submitAudit.disabled = false;
    }
}

function queuedTaskFromSubmission(response) {
    const repository = state.repositories.find(item => item.projectId === response.projectId);
    return {
        taskId: response.taskId,
        projectId: response.projectId,
        projectName: response.projectName,
        repositoryUrl: repository?.repositoryUrl || '',
        baseCommit: response.baseCommit,
        targetCommit: response.targetCommit,
        mergeBase: response.mergeBase,
        changeSummary: '',
        status: response.status || 'UPLOADED',
        progress: Number(response.progress || 0),
        currentStage: response.currentStage || '等待扫描',
        errorMessage: null,
        findingCount: 0,
        agentRunCount: 0,
        modelCallCount: 0,
        toolCallCount: 0,
        createdAt: response.createdAt || new Date().toISOString(),
        completedAt: null
    };
}

function renderQueuedTask(task) {
    seedEvents(task.taskId, []);
    ui.taskDetail.replaceChildren(buildTaskDetail(task, [], [], [], []));
    ui.taskDetail.dataset.taskId = task.taskId;
    state.renderedTaskId = task.taskId;
    state.renderedTaskStatus = task.status;
    state.renderedFindingCount = 0;
    connectEventStream(task.taskId);
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
    const previous = {
        baseBranch: ui.baseBranch.value,
        baseCommit: ui.baseCommit.value,
        targetBranch: ui.targetBranch.value,
        targetCommit: ui.targetCommit.value
    };
    state.commits = (Array.isArray(commits) ? commits : [])
        .slice()
        .sort((left, right) => commitTimestamp(right) - commitTimestamp(left));
    const branches = [...new Set(state.commits.flatMap(commit => commit.branches || []))];
    const repository = state.repositories.find(item => item.projectId === ui.repositorySelect.value);
    const defaultBranch = repository?.defaultBranch || '';
    branches.sort((left, right) => {
        if (left === defaultBranch) return -1;
        if (right === defaultBranch) return 1;
        return left.localeCompare(right, 'zh-CN');
    });
    populateBranchSelect(ui.baseBranch, branches, previous.baseBranch, defaultBranch);
    populateBranchSelect(ui.targetBranch, branches, previous.targetBranch, defaultBranch);
    populateBranchCommits('target', previous.targetCommit);
    populateBranchCommits('base', previous.baseCommit);
}

function populateBranchSelect(select, branches, previousBranch, defaultBranch) {
    select.replaceChildren();
    if (!branches.length) {
        select.add(new Option('暂无可用分支', ''));
        select.disabled = true;
        return;
    }
    branches.forEach(branch => select.add(new Option(branch, branch)));
    const selected = branches.includes(previousBranch) ? previousBranch
        : branches.includes(defaultBranch) ? defaultBranch : branches[0];
    select.value = selected;
    select.disabled = false;
}

function populateBranchCommits(side, preferredCommit = null) {
    const branchSelect = side === 'base' ? ui.baseBranch : ui.targetBranch;
    const commitSelect = side === 'base' ? ui.baseCommit : ui.targetCommit;
    const hint = side === 'base' ? ui.baseCommitHint : ui.targetCommitHint;
    const previousCommit = preferredCommit || commitSelect.value;
    const branch = branchSelect.value;
    const matching = state.commits.filter(commit => (commit.branches || []).includes(branch));
    const visible = matching.slice(0, COMMITS_PER_BRANCH_LIMIT);
    commitSelect.replaceChildren();
    if (!visible.length) {
        commitSelect.add(new Option('该分支暂无可用提交', ''));
        commitSelect.disabled = true;
        hint.textContent = '无可用提交';
        return;
    }
    visible.forEach(commit => {
        const label = `${commit.shortSha || commit.sha?.slice(0, 8)} · ${commit.message || '无提交说明'} · ${formatTime(commit.committedAt)}`;
        commitSelect.add(new Option(label, commit.sha));
    });
    commitSelect.disabled = false;
    const preferredAvailable = visible.some(commit => commit.sha === previousCommit);
    if (preferredAvailable) {
        commitSelect.value = previousCommit;
    } else if (side === 'base' && branch === ui.targetBranch.value && visible.length > 1) {
        commitSelect.selectedIndex = 1;
    } else {
        commitSelect.selectedIndex = 0;
    }
    hint.textContent = matching.length > COMMITS_PER_BRANCH_LIMIT
        ? `当前可用 ${matching.length} 条，仅显示最新 ${COMMITS_PER_BRANCH_LIMIT} 条`
        : `当前可用 ${matching.length} 条 · 按时间从新到旧`;
}

function commitTimestamp(commit) {
    const timestamp = new Date(commit.committedAt || 0).getTime();
    return Number.isNaN(timestamp) ? 0 : timestamp;
}

async function loadTasks({ forceDetail = false, notify = false } = {}) {
    const priorityRefresh = forceDetail || notify;
    if (state.submittingAudit && !priorityRefresh) return;
    if (state.loadingTasks && !priorityRefresh) return;
    const requestSequence = ++state.taskRequestSequence;
    state.loadingTasks = true;
    try {
        const tasks = await fetchJson('/api/tasks');
        if (requestSequence !== state.taskRequestSequence) return;
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
        if (statusChanged) await refreshFileChanges(task);
        state.renderedTaskStatus = task.status;
    } catch (error) {
        if (requestSequence !== state.taskRequestSequence) return;
        ui.taskList.replaceChildren(emptyState(`无法读取任务：${error.message}`));
        if (notify) toast(error.message, true);
    } finally {
        if (requestSequence === state.taskRequestSequence) state.loadingTasks = false;
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
            el('small', '', `增量扫描 · ${task.currentStage || statusText(task.status)} · ${formatTime(task.createdAt)}`));
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
            el('small', '', `增量扫描 · ${task.currentStage || '等待启动'}`));
        if (!TERMINAL_STATUSES.has(task.status)) {
            const progress = el('span', 'entity-progress');
            const fill = el('i');
            fill.style.width = `${clampProgress(task.progress)}%`;
            progress.append(fill);
            copy.append(progress);
        } else if (TERMINAL_STATUSES.has(task.status)) {
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
        const [findings, events, agents, fileChanges] = await Promise.all([
            task.findingCount > 0 || task.status === 'COMPLETED'
                ? fetchJson(`/api/tasks/${taskId}/findings`) : Promise.resolve([]),
            fetchJson(`/api/tasks/${taskId}/events`),
            fetchJson(`/api/tasks/${taskId}/agents`),
            fetchJson(`/api/tasks/${taskId}/changes`).catch(() => [])
        ]);
        if (state.selectedTaskId !== taskId || selectedTask() !== task) return;
        seedEvents(taskId, events);
        ui.taskDetail.replaceChildren(buildTaskDetail(task, findings, agents, events, fileChanges));
        ui.taskDetail.dataset.taskId = taskId;
        state.renderedTaskId = taskId;
        state.renderedTaskStatus = task.status;
        state.renderedFindingCount = task.findingCount;
        if (state.route === 'tasks' && !TERMINAL_STATUSES.has(task.status)) connectEventStream(taskId);
        else closeEventStream();
    } catch (error) {
        if (state.selectedTaskId !== taskId || selectedTask() !== task) return;
        ui.taskDetail.replaceChildren(emptyState(`无法读取任务详情：${error.message}`));
    }
}

function buildTaskDetail(task, findings, agents, events, fileChanges) {
    const fragment = document.createDocumentFragment();
    const header = el('header', 'detail-header');
    const title = el('div', 'detail-header-copy');
    title.append(el('p', 'detail-kicker', `INCREMENTAL / ${statusText(task.status)}`),
        el('h3', '', task.projectName),
        el('p', 'detail-subtitle', `${commitRange(task)} · ${formatTime(task.createdAt)}`),
        el('p', 'detail-subtitle', task.changeSummary || task.repositoryUrl || '暂无变更摘要'));
    const actions = el('div', 'detail-actions');
    renderTaskActions(actions, task);
    header.append(title, actions);

    const body = el('div', 'detail-body');
    body.append(buildProgress(task));
    if (task.errorMessage) body.append(el('p', 'error-banner', task.errorMessage));
    body.append(buildTaskStats(task, events.length));
    body.append(buildFileChanges(fileChanges));
    body.append(buildInvestigation(agents, events), buildFindings(findings, task.status));
    fragment.append(header, body);
    return fragment;
}

function renderTaskActions(actions, task) {
    actions.replaceChildren();
    actions.dataset.status = task.status;
    if (task.status === 'COMPLETED') {
        const report = el('a', 'button primary', '查看审计报告 ↗');
        report.href = `/api/tasks/${task.taskId}/report.html`;
        report.target = '_blank';
        report.rel = 'noopener';
        actions.append(report);
    } else if (!TERMINAL_STATUSES.has(task.status)) {
        const waiting = el('button', 'button secondary', '报告生成中');
        waiting.disabled = true;
        const cancel = el('button', 'button danger',
            state.cancellingTaskIds.has(task.taskId) ? '正在中断…' : '中断审计');
        cancel.type = 'button';
        cancel.disabled = state.cancellingTaskIds.has(task.taskId);
        cancel.addEventListener('click', () => cancelAudit(task, cancel));
        actions.append(waiting, cancel);
    } else {
        const terminal = el('button', 'button secondary',
            task.status === 'CANCELLED' ? '审计已中断' : '审计失败');
        terminal.disabled = true;
        actions.append(terminal);
    }
}

async function cancelAudit(task, button) {
    if (TERMINAL_STATUSES.has(task.status) || state.cancellingTaskIds.has(task.taskId)) return;
    const confirmed = await confirmAction({
        title: '中断审计任务',
        message: `确定中断“${task.projectName}”的本次增量审计吗？已经生成的调查轨迹会保留，但不会生成正式漏洞报告。`,
        confirmLabel: '确认中断',
        danger: true
    });
    if (!confirmed) return;

    state.cancellingTaskIds.add(task.taskId);
    button.disabled = true;
    button.textContent = '正在中断…';
    try {
        const result = await fetchJson(`/api/tasks/${task.taskId}/cancel`, { method: 'POST' });
        const index = state.tasks.findIndex(item => item.taskId === task.taskId);
        if (index >= 0 && result.task) state.tasks[index] = result.task;
        closeEventStream();
        state.renderedTaskId = null;
        await loadTasks({ forceDetail: true });
        toast(result.message || '审计任务已中断。');
    } catch (error) {
        toast(error.message, true);
        button.disabled = false;
        button.textContent = '中断审计';
    } finally {
        state.cancellingTaskIds.delete(task.taskId);
    }
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
        const message = status === 'COMPLETED'
            ? '本轮审计没有产生通过 Critic 证据门槛的问题。'
            : status === 'CANCELLED'
                ? '审计任务已中断，不生成正式漏洞列表。'
                : status === 'FAILED'
                    ? '审计任务失败，未生成正式漏洞列表。'
                    : '当前正在调查，确认结果将在此出现。';
        container.append(emptyState(message, true));
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
    const main = (index < 0 ? description : description.slice(0, index)).trim();
    const review = index < 0 ? '' : description.slice(index + marker.length).trim();
    const content = main || review;
    if (!content) return;
    const section = el('section', 'finding-copy-section');
    section.append(el('h5', '', '漏洞说明'), el('p', 'finding-description', content));
    container.append(section);
}

function buildFindingEvidence(value) {
    const section = el('section', 'finding-copy-section');
    section.append(el('h5', '', '代码证据'));
    const list = el('div', 'finding-evidence-list');
    splitFindingEvidence(value).forEach((chunk, index) => {
        const card = el('article', 'finding-evidence-chunk');
        const header = el('header');
        header.append(el('b', '', `代码证据 ${index + 1}`),
            el('span', '', chunk.location || '代码上下文'));
        const code = buildEvidenceCode(chunk.code || '暂无代码证据');
        card.append(header, code);
        list.append(card);
    });
    section.append(list);
    return section;
}

function splitFindingEvidence(value) {
    const lines = String(value || '').split(/\r?\n/);
    const chunks = [];
    let current = null;
    lines.forEach(line => {
        const match = line.match(/^\[CHUNK\s+(\d+)]\s*(.*)$/);
        if (match) {
            if (current) chunks.push(current);
            current = {id: match[1], location: match[2].trim(), lines: []};
            return;
        }
        if (!current) current = {id: '', location: '', lines: []};
        current.lines.push(line);
    });
    if (current) chunks.push(current);
    const normalized = chunks.map(chunk => ({
        id: chunk.id,
        location: chunk.location,
        code: chunk.lines.join('\n').trim()
    })).filter(chunk => chunk.id || chunk.location || chunk.code);
    return normalized.length ? normalized : [{id: '', location: '', code: '暂无代码证据'}];
}

function buildEvidenceCode(value) {
    const code = el('div', 'evidence-code');
    String(value || '').split(/\r?\n/).forEach(line => {
        const match = line.match(/^(>>> |\s{4})(\s*\d+)\s*\|\s?(.*)$/);
        const row = el('div', `evidence-code-line${line.startsWith('>>> ') ? ' vulnerable' : ''}`);
        if (match) {
            row.append(el('span', 'evidence-line-number', match[2].trim()),
                el('code', '', match[3] || ' '));
        } else if (line.trim() === '…') {
            row.classList.add('ellipsis');
            row.append(el('span', 'evidence-line-number', '…'), el('code', '', ' '));
        } else {
            row.append(el('span', 'evidence-line-number', ''), el('code', '', line || ' '));
        }
        code.append(row);
    });
    return code;
}

function buildFileChanges(fileChanges) {
    const changes = Array.isArray(fileChanges) ? fileChanges : [];
    const section = el('section', 'detail-section');
    section.id = 'file-change-section';
    const panel = el('details', 'file-change-panel');
    const heading = el('summary', 'file-change-heading');
    const title = el('span', 'file-change-title');
    title.append(el('small', '', 'BASE → TARGET'), el('strong', '', '提交代码变化'));
    const additions = changes.reduce((total, change) => total + Number(change.additions || 0), 0);
    const deletions = changes.reduce((total, change) => total + Number(change.deletions || 0), 0);
    const totals = el('span', 'file-change-totals');
    totals.append(el('b', '', `${changes.length} 个文件`),
        el('small', 'file-additions', `+${additions}`),
        el('small', 'file-deletions', `−${deletions}`));
    heading.append(title, totals);
    const body = el('div', 'file-change-list');
    if (!changes.length) {
        body.append(emptyState('暂未读取到两次提交之间的文件变化。', true));
    } else {
        changes.forEach(change => body.append(buildFileChangeCard(change)));
    }
    panel.append(heading, body);
    section.append(panel);
    return section;
}

function buildFileChangeCard(change) {
    const card = el('details', 'file-change-card');
    const summary = el('summary');
    const identity = el('span', 'file-change-identity');
    identity.append(el('strong', '', fileChangePath(change)),
        el('small', '', fileChangeTypeLabel(change.changeType)));
    const stats = el('span', 'file-change-stats');
    stats.append(el('b', 'file-additions', `+${Number(change.additions || 0)}`),
        el('b', 'file-deletions', `−${Number(change.deletions || 0)}`));
    summary.append(identity, stats);
    const body = el('div', 'file-change-body');
    body.append(buildFileDiff(change.contextText));
    card.append(summary, body);
    return card;
}

function buildFileDiff(contextText) {
    const diff = el('div', 'file-diff');
    const content = String(contextText || '').trimEnd();
    if (!content) {
        diff.append(el('p', 'file-diff-empty', '该文件没有可展示的文本差异。'));
        return diff;
    }
    content.split(/\r?\n/).forEach(line => {
        const hunk = line.startsWith('@@');
        const added = !hunk && line.startsWith('+ ');
        const deleted = !hunk && line.startsWith('- ');
        const row = el('div', `file-diff-line${hunk ? ' hunk' : added ? ' added' : deleted ? ' deleted' : ''}`);
        row.append(el('span', 'file-diff-mark', hunk ? '···' : added ? '+' : deleted ? '−' : ''),
            el('code', '', hunk ? line : line.slice(2)));
        diff.append(row);
    });
    return diff;
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
    const actions = ui.taskDetail.querySelector('.detail-actions');
    if (actions && actions.dataset.status !== task.status) renderTaskActions(actions, task);
    if (TERMINAL_STATUSES.has(task.status)) closeEventStream();
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

async function refreshFileChanges(task) {
    try {
        const changes = await fetchJson(`/api/tasks/${task.taskId}/changes`);
        if (state.selectedTaskId !== task.taskId) return;
        const current = ui.taskDetail.querySelector('#file-change-section');
        if (current) current.replaceWith(buildFileChanges(changes));
    } catch (_) {
        // File changes are supporting context; live investigation remains available.
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
    const source = new EventSource(`/api/tasks/${taskId}/events/stream`);
    source.datasetTaskId = taskId;
    state.eventSource = source;
    source.addEventListener('agent-event', event => {
        try {
            appendAgentEvent(taskId, JSON.parse(event.data));
        } catch (_) { /* Ignore malformed events and wait for the next SSE message. */ }
    });
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
    if (['STARTED', 'COMPLETED', 'CANCELLED', 'ERROR', 'FINDING', 'LOCATION_UNRESOLVED',
        'INSUFFICIENT_EVIDENCE', 'FORMAT_ERROR', 'REJECTED'].includes(event.eventType)) {
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
    const message = withoutInternalChunkIds(toolCall ? summarizeToolCall(event.message)
        : observation ? summarizeObservation(event.message)
            : event.eventType === 'MODEL_CALL' ? summarizeModelCall(event.message)
                : String(event.message || ''));
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

function summarizeModelCall(value) {
    return String(value || '').replace(
        /结合 Recon 架构事实、CodeGraph 调用关系、局部安全语义和 0 条工具观察进行安全判断/g,
        '结合 Recon 架构事实、CodeGraph 调用关系和局部安全语义进行判断'
    );
}

function withoutInternalChunkIds(value) {
    return String(value || '')
        .replace(/\[CHUNK\s+\d+]\s*/gi, '')
        .replace(/\bCHUNK_ID\s*=\s*\d+\b/gi, '相关代码位置')
        .replace(/\b(?:PRIMARY_)?CHUNK(?:_ID)?\s*[:=#]?\s*\d+\b/gi, '相关代码位置')
        .replace(/\b(?:primaryChunkId|chunkId)\s*[:=]\s*\d+\b/gi, '相关代码位置')
        .replace(/代码块\s*[#＃]?\s*\d+/g, '相关代码块')
        .replace(/[ \t]{2,}/g, ' ')
        .trim();
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
    copy.append(el('strong', '', `增量扫描 · ${commitRange(audit)}`),
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
        FAILED: '失败', CANCELLED: '已中断', ACTIVE: '使用中', ARCHIVED: '已归档'
    })[status] || '运行中';
}

function runStatusText(status) {
    return ({ RUNNING: '运行中', COMPLETED: '已完成', FAILED: '失败' })[status] || status || '未知';
}

function agentText(agent) {
    return ({
        RECON: 'Recon Agent', ORCHESTRATOR: 'Triage Orchestrator', SQL_INJECTION: 'SQL 注入 Agent',
        AUTHORIZATION: '权限审计 Agent', SENSITIVE_INFORMATION: '敏感信息审计 Agent',
        STORED_XSS: '存储 XSS Agent', VALIDATION_BYPASS: '验证绕过 Agent',
        CRITIC: 'Critic Agent', REPORT: 'Report Agent'
    })[agent] || agent || 'SYSTEM';
}

function eventTypeText(type) {
    return ({
        STARTED: '启动', MODEL_CALL: '模型调用', REASONING: '推理摘要', PLAN: '审计计划',
        TOOL_CALL: '工具调用', OBSERVATION: '工具观察', HYPOTHESIS: '漏洞假设',
        FINDING: '确认问题', LOCATION_UNRESOLVED: '定位待复核', INSUFFICIENT_EVIDENCE: '证据不足',
        FORMAT_ERROR: '响应异常', REJECTED: '否决', COMPLETED: '完成', CANCELLED: '已中断', ERROR: '错误'
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
        SQL_INJECTION: 'SQL 注入', AUTHORIZATION: '越权漏洞', SENSITIVE_INFORMATION_DISCLOSURE: '敏感信息泄露',
        STORED_XSS: '存储型 XSS', VALIDATION_BYPASS: '验证绕过'
    })[value] || value || '安全问题';
}

function deltaStatusText(value) {
    return ({
        NEW: '变更新增', PERSISTING: '持续存在'
    })[value] || '未分类';
}

function fileChangePath(change) {
    const oldPath = change.oldPath || '';
    const newPath = change.newPath || '';
    if (oldPath && newPath && oldPath !== newPath) return `${oldPath} → ${newPath}`;
    return newPath || oldPath || '未知文件';
}

function fileChangeTypeLabel(changeType) {
    return ({
        ADD: '新增文件', MODIFY: '修改文件', DELETE: '删除文件',
        RENAME: '重命名文件', COPY: '复制文件'
    })[changeType] || changeType || '文件变化';
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
        read_source: '读取目标或候选源码，核对实现细节',
        verify_relation: '验证候选代码与当前审计目标的确定性关系',
        search_symbols: '按符号、注解、路径或文本查找相关代码',
        search_code: '按字面量搜索相关源码',
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
