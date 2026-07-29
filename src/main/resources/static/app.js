const TERMINAL_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);
const state = {
    tasks: [],
    repositories: [],
    managedProjects: [],
    commits: [],
    selectedProjectId: null,
    selectedTaskId: null,
    renderedTaskId: null,
    renderedFindingCount: -1,
    renderedStatus: null,
    loadingTasks: false,
    loadingProjects: false,
    poller: null,
    eventSource: null,
    eventIdsByTask: new Map(),
    eventsByTask: new Map(),
    agentRefreshTimer: null
};

const elements = {
    importForm: document.querySelector('#git-import-form'),
    auditForm: document.querySelector('#audit-form'),
    repositorySelect: document.querySelector('#repository-select'),
    repositoryUrl: document.querySelector('#repository-url'),
    gitUsername: document.querySelector('#git-username'),
    gitToken: document.querySelector('#git-token'),
    scanMode: document.querySelector('#scan-mode'),
    baseCommitGroup: document.querySelector('#base-commit-group'),
    baseCommit: document.querySelector('#base-commit'),
    targetCommit: document.querySelector('#target-commit'),
    importMessage: document.querySelector('#git-message'),
    auditMessage: document.querySelector('#audit-message'),
    importButton: document.querySelector('#import-button'),
    refreshCommits: document.querySelector('#refresh-commits-button'),
    submit: document.querySelector('#submit-button'),
    refresh: document.querySelector('#refresh-button'),
    refreshProjects: document.querySelector('#refresh-projects-button'),
    includeArchivedProjects: document.querySelector('#include-archived-projects'),
    projectList: document.querySelector('#project-list'),
    projectCount: document.querySelector('#project-count'),
    projectDetail: document.querySelector('#project-detail'),
    taskList: document.querySelector('#task-list'),
    taskCount: document.querySelector('#task-count'),
    detail: document.querySelector('#task-detail'),
    streamState: document.querySelector('#stream-state'),
    metricTasks: document.querySelector('#metric-tasks'),
    metricActive: document.querySelector('#metric-active'),
    metricFindings: document.querySelector('#metric-findings'),
    metricModelCalls: document.querySelector('#metric-model-calls')
};

elements.importForm.addEventListener('submit', async event => {
    event.preventDefault();
    elements.importButton.disabled = true;
    showImportMessage('正在只读克隆仓库并读取提交记录…');
    try {
        const data = new FormData(elements.importForm);
        const response = await fetchJson('/api/projects/git', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(Object.fromEntries(data.entries()))
        });
        elements.gitToken.value = '';
        await loadRepositories(response.project.projectId);
        await loadManagedProjects(response.project.projectId);
        populateCommits(response.commits);
        showImportMessage(response.message);
    } catch (error) {
        showImportMessage(error.message, true);
    } finally {
        elements.importButton.disabled = false;
    }
});

elements.auditForm.addEventListener('submit', async event => {
    event.preventDefault();
    const projectId = elements.repositorySelect.value;
    const targetCommit = elements.targetCommit.value;
    const incremental = elements.scanMode.value === 'INCREMENTAL';
    const baseCommit = incremental ? elements.baseCommit.value : null;
    if (!projectId || !targetCommit || (incremental && !baseCommit)) {
        showAuditMessage('请选择仓库和提交范围。', true);
        return;
    }
    elements.submit.disabled = true;
    showAuditMessage('正在创建 Git 审计任务…');
    try {
        const response = await fetchJson(`/api/projects/${projectId}/audits`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scanMode: elements.scanMode.value, baseCommit, targetCommit })
        });
        state.selectedTaskId = response.taskId;
        state.renderedTaskId = null;
        showAuditMessage(response.message);
        await loadTasks(true);
        document.querySelector('#audit-workspace').scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        showAuditMessage(error.message, true);
    } finally {
        elements.submit.disabled = false;
    }
});

elements.repositorySelect.addEventListener('change', () => loadCommits());
elements.scanMode.addEventListener('change', updateScanMode);
elements.refreshCommits.addEventListener('click', () => refreshCommits());
elements.refresh.addEventListener('click', () => loadTasks(true));
elements.refreshProjects.addEventListener('click', () => loadManagedProjects(state.selectedProjectId));
elements.includeArchivedProjects.addEventListener('change', () => loadManagedProjects());

async function loadRepositories(selectedProjectId = null) {
    state.repositories = await fetchJson('/api/projects');
    elements.repositorySelect.replaceChildren(new Option('请选择仓库', ''));
    state.repositories.forEach(repository => {
        const option = new Option(`${repository.name} / ${repository.defaultBranch}`, repository.projectId);
        elements.repositorySelect.add(option);
    });
    const selected = selectedProjectId || elements.repositorySelect.value || state.repositories[0]?.projectId;
    if (selected) {
        elements.repositorySelect.value = selected;
        await loadCommits();
    } else {
        populateCommits([]);
    }
}

async function loadManagedProjects(selectedProjectId = null) {
    if (state.loadingProjects) return;
    state.loadingProjects = true;
    try {
        const includeArchived = elements.includeArchivedProjects.checked;
        state.managedProjects = await fetchJson(`/api/projects?includeArchived=${includeArchived}`);
        const requested = selectedProjectId || state.selectedProjectId;
        state.selectedProjectId = state.managedProjects.some(project => project.projectId === requested)
            ? requested : state.managedProjects[0]?.projectId || null;
        renderProjectList();
        if (state.selectedProjectId) {
            await renderSelectedProject();
        } else {
            renderEmptyProjectDetail();
        }
    } catch (error) {
        elements.projectList.replaceChildren(node('div', 'empty-state', `无法读取项目：${error.message}`));
    } finally {
        state.loadingProjects = false;
    }
}

function renderProjectList() {
    elements.projectList.replaceChildren();
    elements.projectCount.textContent = `${state.managedProjects.length} ITEMS`;
    if (!state.managedProjects.length) {
        elements.projectList.append(node('div', 'empty-state', '暂无扫描项目'));
        return;
    }
    state.managedProjects.forEach((project, index) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = `project-card${project.projectId === state.selectedProjectId ? ' active' : ''}`
            + `${project.archived ? ' archived' : ''}`;
        item.addEventListener('click', () => selectManagedProject(project.projectId));
        const copy = document.createElement('span');
        copy.className = 'project-card-copy';
        copy.append(node('strong', '', project.name),
            node('small', '', project.repositoryUrl),
            node('small', '', project.defaultBranch || '未识别默认分支'));
        item.append(node('span', 'project-index', String(index + 1).padStart(2, '0')), copy,
            node('span', `project-state${project.archived ? ' archived' : ''}`,
                project.archived ? '已归档' : '使用中'));
        elements.projectList.append(item);
    });
}

async function selectManagedProject(projectId) {
    if (state.selectedProjectId === projectId) return;
    state.selectedProjectId = projectId;
    renderProjectList();
    await renderSelectedProject();
}

async function renderSelectedProject() {
    const project = state.managedProjects.find(item => item.projectId === state.selectedProjectId);
    if (!project) return renderEmptyProjectDetail();
    const requestedId = project.projectId;
    elements.projectDetail.replaceChildren(node('div', 'empty-state', '正在读取项目扫描历史…'));
    try {
        const audits = await fetchJson(`/api/projects/${project.projectId}/audits`);
        if (state.selectedProjectId !== requestedId) return;
        elements.projectDetail.replaceChildren(buildProjectDetail(project, audits));
    } catch (error) {
        elements.projectDetail.replaceChildren(node('div', 'empty-state', `无法读取项目详情：${error.message}`));
    }
}

function buildProjectDetail(project, audits) {
    const fragment = document.createDocumentFragment();
    const head = document.createElement('header');
    head.className = 'project-detail-head';
    const title = document.createElement('div');
    title.append(node('p', 'kicker', project.archived ? 'ARCHIVED PROJECT' : 'ACTIVE PROJECT'),
        node('h3', '', project.name), node('p', 'project-repository', project.repositoryUrl));
    head.append(title, node('span', `project-status-badge${project.archived ? ' archived' : ''}`,
        project.archived ? '已归档' : '使用中'));

    const metadata = document.createElement('div');
    metadata.className = 'project-metadata';
    metadata.append(projectMeta('DEFAULT BRANCH', project.defaultBranch || '—'),
        projectMeta('CREATED', formatTime(project.createdAt)),
        projectMeta('UPDATED', formatTime(project.updatedAt)),
        projectMeta('AUDIT HISTORY', String(audits.length)));

    const editForm = document.createElement('form');
    editForm.className = 'project-edit-form';
    const nameField = projectField('项目名称', 'input');
    nameField.control.name = 'name';
    nameField.control.maxLength = 200;
    nameField.control.required = true;
    nameField.control.value = project.name;
    const descriptionField = projectField('项目描述', 'textarea');
    descriptionField.control.name = 'description';
    descriptionField.control.maxLength = 1000;
    descriptionField.control.rows = 4;
    descriptionField.control.placeholder = '记录项目用途或扫描范围（可选）';
    descriptionField.control.value = project.description || '';
    const save = node('button', 'project-primary-action', '保存基本信息');
    save.type = 'submit';
    const message = node('p', 'project-action-message', '');
    editForm.append(nameField.wrapper, descriptionField.wrapper, save, message);
    editForm.addEventListener('submit', event => saveProjectDetails(event, project.projectId, save, message));

    const history = document.createElement('section');
    history.className = 'project-history';
    const historyHead = document.createElement('div');
    historyHead.className = 'project-subhead';
    historyHead.append(node('h4', '', '扫描历史'), node('span', '', `${audits.length} AUDITS`));
    const historyList = document.createElement('div');
    historyList.className = 'project-history-list';
    if (!audits.length) {
        historyList.append(node('div', 'empty-state compact', '该项目还没有扫描记录'));
    } else {
        audits.forEach(audit => historyList.append(projectHistoryRow(audit)));
    }
    history.append(historyHead, historyList);

    const lifecycle = document.createElement('section');
    lifecycle.className = 'project-lifecycle';
    const lifecycleCopy = document.createElement('div');
    lifecycleCopy.append(node('h4', '', project.archived ? '恢复与数据清理' : '项目归档'),
        node('p', '', project.archived
            ? '恢复后可以继续刷新仓库和创建扫描；清理只删除扫描派生数据，保留裸 Git 仓库。'
            : '归档后停止刷新和新建扫描，已有扫描记录与报告继续保留。'));
    const lifecycleActions = document.createElement('div');
    lifecycleActions.className = 'project-lifecycle-actions';
    const archiveAction = node('button', project.archived ? 'project-secondary-action' : 'project-warning-action',
        project.archived ? '恢复项目' : '归档项目');
    archiveAction.type = 'button';
    archiveAction.addEventListener('click', () => toggleProjectArchive(project, archiveAction));
    lifecycleActions.append(archiveAction);
    if (project.archived) {
        const cleanup = node('button', 'project-danger-action', '清空扫描数据');
        cleanup.type = 'button';
        cleanup.disabled = audits.length === 0;
        cleanup.addEventListener('click', () => cleanupProjectData(project, cleanup));
        lifecycleActions.append(cleanup);
    }
    lifecycle.append(lifecycleCopy, lifecycleActions);

    fragment.append(head, metadata, editForm, history, lifecycle);
    return fragment;
}

function projectMeta(label, value) {
    const item = document.createElement('span');
    item.append(node('small', '', label), node('b', '', value));
    return item;
}

function projectField(labelText, type) {
    const wrapper = document.createElement('label');
    wrapper.className = 'project-field';
    wrapper.append(node('span', '', labelText));
    const control = document.createElement(type);
    wrapper.append(control);
    return { wrapper, control };
}

function projectHistoryRow(audit) {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'project-history-row';
    row.addEventListener('click', async () => {
        state.selectedTaskId = audit.taskId;
        state.renderedTaskId = null;
        await loadTasks(true);
        document.querySelector('#audit-workspace').scrollIntoView({ behavior: 'smooth' });
    });
    const commit = `${audit.baseCommit ? `${audit.baseCommit.slice(0, 8)} → ` : ''}`
        + `${audit.targetCommit?.slice(0, 8) || '—'}`;
    const copy = document.createElement('span');
    copy.append(node('strong', '', `${audit.scanMode === 'INCREMENTAL' ? '增量扫描' : '全量扫描'} · ${commit}`),
        node('small', '', `${formatTime(audit.createdAt)} · ${audit.findingCount} 个确认问题`));
    row.append(copy, node('span', `status-pill${audit.status === 'FAILED' ? ' failed' : ''}`,
        statusText(audit.status)));
    return row;
}

async function saveProjectDetails(event, projectId, button, message) {
    event.preventDefault();
    button.disabled = true;
    message.textContent = '正在保存…';
    try {
        const data = new FormData(event.currentTarget);
        await fetchJson(`/api/projects/${projectId}`, {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(Object.fromEntries(data.entries()))
        });
        message.textContent = '项目基本信息已保存。';
        await Promise.all([loadRepositories(), loadManagedProjects(projectId)]);
    } catch (error) {
        message.textContent = error.message;
        message.classList.add('error');
    } finally {
        button.disabled = false;
    }
}

async function toggleProjectArchive(project, button) {
    const action = project.archived ? '恢复' : '归档';
    if (!window.confirm(`确定要${action}项目“${project.name}”吗？`)) return;
    button.disabled = true;
    try {
        await fetchJson(`/api/projects/${project.projectId}/${project.archived ? 'restore' : 'archive'}`,
            { method: 'POST' });
        if (!project.archived) elements.includeArchivedProjects.checked = true;
        await Promise.all([loadRepositories(), loadManagedProjects(project.projectId)]);
    } catch (error) {
        window.alert(error.message);
        button.disabled = false;
    }
}

async function cleanupProjectData(project, button) {
    if (!window.confirm(`将永久删除“${project.name}”的全部扫描任务、代码块、向量、漏洞和报告。裸 Git 仓库仍会保留。确定继续吗？`)) return;
    button.disabled = true;
    try {
        const result = await fetchJson(`/api/projects/${project.projectId}/cleanup`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirmation: 'DELETE_SCAN_DATA' })
        });
        state.selectedTaskId = null;
        state.renderedTaskId = null;
        await Promise.all([loadTasks(true), loadManagedProjects(project.projectId)]);
        window.alert(`${result.message}，共删除 ${result.deletedTaskCount} 个扫描任务。`);
    } catch (error) {
        window.alert(error.message);
        button.disabled = false;
    }
}

function renderEmptyProjectDetail() {
    elements.projectDetail.replaceChildren(node('div', 'detail-empty', '暂无可管理的扫描项目'));
}

async function loadCommits() {
    const projectId = elements.repositorySelect.value;
    if (!projectId) {
        populateCommits([]);
        return;
    }
    try {
        populateCommits(await fetchJson(`/api/projects/${projectId}/commits?limit=200`));
    } catch (error) {
        showAuditMessage(error.message, true);
    }
}

async function refreshCommits() {
    const projectId = elements.repositorySelect.value;
    if (!projectId) return showAuditMessage('请先选择仓库。', true);
    elements.refreshCommits.disabled = true;
    try {
        const commits = await fetchJson(`/api/projects/${projectId}/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: elements.gitUsername.value, accessToken: elements.gitToken.value })
        });
        elements.gitToken.value = '';
        populateCommits(commits);
        showAuditMessage('提交记录已刷新。');
    } catch (error) {
        showAuditMessage(error.message, true);
    } finally {
        elements.refreshCommits.disabled = false;
    }
}

function populateCommits(commits) {
    state.commits = commits || [];
    elements.targetCommit.replaceChildren();
    elements.baseCommit.replaceChildren();
    state.commits.forEach(commit => {
        const label = `${commit.shortSha} · ${commit.message} · ${formatTime(commit.committedAt)}`;
        elements.targetCommit.add(new Option(label, commit.sha));
        elements.baseCommit.add(new Option(label, commit.sha));
    });
    if (state.commits.length > 1) elements.baseCommit.selectedIndex = 1;
    updateScanMode();
}

function updateScanMode() {
    const incremental = elements.scanMode.value === 'INCREMENTAL';
    elements.baseCommitGroup.classList.toggle('hidden', !incremental);
    elements.baseCommit.required = incremental;
}

function showImportMessage(message, error = false) {
    elements.importMessage.textContent = message;
    elements.importMessage.style.color = error ? '#ff8b70' : '#c9ff45';
}

function showAuditMessage(message, error = false) {
    elements.auditMessage.textContent = message;
    elements.auditMessage.style.color = error ? '#ff8b70' : '#c9ff45';
}

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
        const statusChanged = selected.status !== state.renderedStatus;
        const needsFindings = selected.findingCount !== state.renderedFindingCount
            || statusChanged;
        state.renderedStatus = selected.status;
        if (needsFindings) await refreshFindings(selected);
        if (selected.scanMode === 'INCREMENTAL' && statusChanged) await refreshMethodChanges(selected);
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
        const [findings, events, agents, methodChanges] = await Promise.all([
            task.findingCount > 0 || task.status === 'COMPLETED'
                ? fetchJson(`/api/tasks/${task.taskId}/findings`) : Promise.resolve([]),
            fetchJson(`/api/tasks/${task.taskId}/events`),
            fetchJson(`/api/tasks/${task.taskId}/agents`),
            task.scanMode === 'INCREMENTAL'
                ? fetchJson(`/api/tasks/${task.taskId}/method-changes`).catch(() => []) : Promise.resolve([])
        ]);
        if (state.selectedTaskId !== requestedTaskId) return;
        seedEvents(task.taskId, events);
        elements.detail.replaceChildren(buildTaskDetail(task, findings, agents, events, methodChanges));
        state.renderedTaskId = task.taskId;
        state.renderedFindingCount = task.findingCount;
        state.renderedStatus = task.status;
        connectEventStream(task.taskId);
    } catch (error) {
        elements.detail.replaceChildren(node('div', 'empty-state', `无法读取任务详情：${error.message}`));
    }
}

function buildTaskDetail(task, findings, agents, events, methodChanges) {
    const fragment = document.createDocumentFragment();
    const head = document.createElement('div');
    head.className = 'detail-head';
    const title = document.createElement('div');
    title.append(node('h3', '', task.projectName),
        node('p', '', `${task.scanMode === 'INCREMENTAL' ? '增量' : '全量'} · `
            + `${task.baseCommit ? `${task.baseCommit.slice(0, 8)} → ` : ''}`
            + `${task.targetCommit?.slice(0, 8) || '—'} / ${formatTime(task.createdAt)}`),
        node('p', '', task.changeSummary || task.repositoryUrl || ''));
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
    fragment.append(metrics);
    if (task.scanMode === 'INCREMENTAL') fragment.append(buildMethodChangeSection(methodChanges));
    fragment.append(investigation, findingSection);
    return fragment;
}

function buildMethodChangeSection(methodChanges) {
    const changes = Array.isArray(methodChanges) ? methodChanges : [];
    const groups = groupMethodChanges(changes);
    const section = document.createElement('section');
    section.id = 'method-change-section';
    section.className = 'semantic-change-section';

    const panel = document.createElement('details');
    panel.className = 'semantic-change-panel';
    panel.open = changes.some(change => change.changeKind === 'GUARD_REMOVED');
    const summary = document.createElement('summary');
    summary.className = 'semantic-change-heading';
    const heading = document.createElement('span');
    heading.append(node('small', '', 'INCREMENTAL SEMANTIC DIFF'),
        node('strong', '', '方法语义变化'));
    const overview = document.createElement('span');
    overview.className = 'semantic-change-overview';
    overview.append(node('b', '', String(groups.length)),
        node('small', '', `${groups.length === 1 ? 'METHOD' : 'METHODS'} / ${changes.length} FACTS`));
    summary.append(heading, overview);

    const body = document.createElement('div');
    body.className = 'semantic-change-body';
    if (!changes.length) {
        body.append(node('div', 'semantic-change-empty', '本次增量扫描未识别到 Java 方法级语义变化。'));
    } else {
        const stats = document.createElement('div');
        stats.className = 'semantic-change-stats';
        methodChangeKinds().forEach(kind => {
            const count = changes.filter(change => change.changeKind === kind).length;
            if (!count) return;
            const stat = node('span', `method-kind ${methodChangeTone(kind)}`, '');
            stat.append(node('b', '', String(count)), document.createTextNode(methodChangeLabel(kind)));
            stats.append(stat);
        });
        const list = document.createElement('div');
        list.className = 'method-change-list';
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
        const key = [change.basePath, change.targetPath, change.baseSymbol, change.targetSymbol,
            change.methodName].map(value => value || '').join('|');
        if (!grouped.has(key)) grouped.set(key, {primary: change, changes: []});
        grouped.get(key).changes.push(change);
    });
    return [...grouped.values()];
}

function buildMethodChangeCard(group) {
    const change = group.primary;
    const card = document.createElement('details');
    card.className = 'method-change-card';
    card.open = group.changes.some(item => item.changeKind === 'GUARD_REMOVED');
    const summary = document.createElement('summary');
    summary.className = 'method-change-summary';
    const copy = document.createElement('span');
    copy.className = 'method-change-copy';
    copy.append(node('strong', '', change.targetSymbol || change.baseSymbol || change.methodName || '未命名方法'),
        node('small', '', methodChangeLocation(change)));
    const badges = document.createElement('span');
    badges.className = 'method-change-badges';
    [...new Set(group.changes.map(item => item.changeKind))].forEach(kind => {
        badges.append(node('span', `method-kind ${methodChangeTone(kind)}`, methodChangeLabel(kind)));
    });
    summary.append(copy, badges);

    const body = document.createElement('div');
    body.className = 'method-change-card-body';
    const facts = document.createElement('ul');
    facts.className = 'method-change-facts';
    group.changes.forEach(item => {
        facts.append(node('li', '', item.details || methodChangeLabel(item.changeKind)));
    });
    const compare = document.createElement('div');
    compare.className = 'method-code-compare';
    compare.append(buildMethodCodePane('BASE', change.basePath, change.baseStartLine, change.baseEndLine,
            change.baseContent, '基线提交中不存在该方法。'),
        buildMethodCodePane('TARGET', change.targetPath, change.targetStartLine, change.targetEndLine,
            change.targetContent, '目标提交中已删除该方法。'));
    body.append(facts, compare);
    card.append(summary, body);
    return card;
}

function buildMethodCodePane(label, path, startLine, endLine, content, emptyText) {
    const pane = document.createElement('section');
    pane.className = 'method-code-pane';
    const heading = document.createElement('div');
    heading.append(node('b', '', label), node('span', '', methodLineLocation(path, startLine, endLine)));
    const code = document.createElement('pre');
    code.textContent = content || emptyText;
    if (!content) code.classList.add('empty');
    pane.append(heading, code);
    return pane;
}

function methodChangeKinds() {
    return ['GUARD_REMOVED', 'GUARD_ADDED', 'SIGNATURE_CHANGED',
        'METHOD_ADDED', 'METHOD_MODIFIED', 'METHOD_DELETED'];
}

function methodChangeLabel(kind) {
    return ({
        METHOD_ADDED: '方法新增',
        METHOD_MODIFIED: '方法修改',
        METHOD_DELETED: '方法删除',
        SIGNATURE_CHANGED: '签名变化',
        GUARD_ADDED: '防护新增',
        GUARD_REMOVED: '防护删除'
    })[kind] || kind || '未知变化';
}

function methodChangeTone(kind) {
    if (kind === 'GUARD_REMOVED' || kind === 'METHOD_DELETED') return 'danger';
    if (kind === 'GUARD_ADDED') return 'safe';
    if (kind === 'SIGNATURE_CHANGED') return 'attention';
    return 'neutral';
}

function methodChangeLocation(change) {
    return methodLineLocation(change.targetPath || change.basePath,
        change.targetStartLine ?? change.baseStartLine,
        change.targetEndLine ?? change.baseEndLine);
}

function methodLineLocation(path, startLine, endLine) {
    const file = path || '未知文件';
    if (startLine == null) return file;
    return `${file}:${startLine}${endLine != null && endLine !== startLine ? `-${endLine}` : ''}`;
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

async function refreshMethodChanges(task) {
    try {
        const methodChanges = await fetchJson(`/api/tasks/${task.taskId}/method-changes`);
        if (state.selectedTaskId !== task.taskId) return;
        const current = elements.detail.querySelector('#method-change-section');
        if (current) current.replaceWith(buildMethodChangeSection(methodChanges));
    } catch (ignored) {
        // 下一个任务状态变化时会重试，不影响实时事件流和漏洞结果展示。
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
        node('small', '', `${severityText(finding.severity)} / 可信度${confidenceText(finding.confidence)}`
            + ` / ${deltaStatusText(finding.deltaStatus)}`));
    const body = document.createElement('div');
    body.className = 'finding-body';
    const location = `${finding.filePath}:${finding.startLine}`
        + `${finding.endLine && finding.endLine !== finding.startLine ? `-${finding.endLine}` : ''}`;
    body.append(node('p', 'vulnerability-location', `实际漏洞位置：${location}`
        + `${finding.endpoint ? ` · ${finding.endpoint}` : ''}`));
    appendFindingDescription(body, finding.description);
    body.append(buildFindingEvidence(finding.evidence), node('p', '', `修复建议：${finding.remediation}`));
    details.append(summary, body);
    return details;
}

function buildFindingEvidence(value) {
    const code = document.createElement('pre');
    code.className = 'finding-evidence';
    String(value || '').split(/\r?\n/).forEach(line => {
        const row = document.createElement('span');
        row.textContent = line;
        if (line.startsWith('>>> ')) row.className = 'vulnerable-line';
        code.append(row);
    });
    return code;
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
    const isToolCall = event.eventType === 'TOOL_CALL';
    const message = isToolCall ? summarizeToolCall(event.message) : String(event.message || '');
    const copy = node('p', 'event-message', message.length > 1000 ? `${message.slice(0, 1000)}…` : message);
    row.append(meta, copy);
    if (!isToolCall && message.length > 1000) {
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
        security_controls: '检索适用于当前目标的安全控制',
        data_access: '追踪当前目标关联的数据访问'
    };
    if (summaries[tool]) return `${tool}：${summaries[tool]}`;
    if (tool && /^[a-z0-9_-]{1,48}$/.test(tool)) return `${tool}：调用只读工具补充审计证据`;
    return '调用只读工具补充当前审计目标的相关证据';
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

function deltaStatusText(value) {
    return ({
        BASELINE: '全量基线', NEW: '变更新增', REGRESSED: '安全回归',
        PERSISTING: '持续存在', AFFECTED: '变更影响'
    })[value] || '未分类';
}

function formatTime(value) {
    return value ? new Intl.DateTimeFormat('zh-CN', {
        year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(new Date(value)) : '—';
}

document.querySelectorAll('.side-nav a').forEach(link => link.addEventListener('click', () => {
    document.querySelectorAll('.side-nav a').forEach(item => item.classList.remove('active'));
    link.classList.add('active');
}));

window.addEventListener('beforeunload', closeEventStream);
loadRepositories().catch(error => showAuditMessage(`无法读取仓库：${error.message}`, true));
loadManagedProjects();
loadTasks();
state.poller = setInterval(loadTasks, 4000);
