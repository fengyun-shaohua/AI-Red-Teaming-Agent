/* 大模型红队评测工具 - 前端交互逻辑 */

// 判定结果中文 + 颜色(与后端 VERDICT_DISPLAY 一致)
const VERDICT_MAP = {
    DANGEROUS_BYPASS: { label: "危险绕过", color: "#e53e3e" },
    SAFE_BYPASS:      { label: "安全绕过", color: "#d69e2e" },
    BLOCKED:          { label: "已拦截",   color: "#38a169" },
    REVIEW:           { label: "待复核",   color: "#718096" },
};

// 内存中的模板/载荷/结果(从服务端初始数据加载,后续同步更新)
let templates = window.__INITIAL__.templates || [];
let payloads = window.__INITIAL__.payloads || [];
let results = window.__INITIAL__.results || [];
let customInputs = window.__INITIAL__.custom_inputs || [];
let editingTplIdx = -1;
let editingPldIdx = -1;
let ws = null;
// 模型列表缓存(target/agent 各一份)与选择浮层当前目标
const MODEL_LISTS = { target: [], agent: [] };
let modelPickerTarget = "target";

// ============================ 初始化 ============================
document.addEventListener("DOMContentLoaded", () => {
    // Tab 切换
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });
    renderTemplates();
    renderPayloads();
    renderResults();
    renderCustomHistory();
});

function switchTab(name) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
    document.getElementById("tab-" + name).classList.remove("hidden");
}

// ============================ 通用工具 ============================
async function api(method, url, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) {
        opt.headers["Content-Type"] = "application/json";
        opt.body = JSON.stringify(body);
    }
    const r = await fetch(url, opt);
    return r.json();
}

function closeDialog(id) {
    document.getElementById(id).classList.add("hidden");
}

function setStatus(text, color = "#1d4ed8") {
    const el = document.getElementById("status_text");
    el.textContent = text;
    el.style.color = color;
}

// ============================ 模板管理 ============================
function renderTemplates() {
    const box = document.getElementById("tpl_list");
    box.innerHTML = "";
    templates.forEach((t, i) => {
        const row = document.createElement("div");
        row.className = "list-row";
        row.innerHTML = `
            <input type="checkbox" class="tpl-check" data-idx="${i}">
            ${t.category ? `<span class="row-tag bg-blue-100 text-blue-700">[${esc(t.category).slice(0,12)}]</span>` : ""}
            <span class="row-name">${esc(t.name)}</span>
            <span class="row-desc">- ${esc((t.description||"").slice(0,40))}</span>
            <button class="row-btn" onclick="event.stopPropagation();editTpl(${i})">编辑</button>
        `;
        box.appendChild(row);
    });
    document.getElementById("tpl_count").textContent = `模板: ${templates.length}`;
}

function openTplDialog() {
    editingTplIdx = -1;
    document.getElementById("tpl_dialog_title").textContent = "添加测试模板";
    ["tpl_name","tpl_category","tpl_desc","tpl_content"].forEach(id => document.getElementById(id).value = "");
    document.getElementById("tpl_dialog").classList.remove("hidden");
}

function editTpl(idx) {
    editingTplIdx = idx;
    const t = templates[idx];
    document.getElementById("tpl_dialog_title").textContent = "编辑测试模板";
    document.getElementById("tpl_name").value = t.name || "";
    document.getElementById("tpl_category").value = t.category || "";
    document.getElementById("tpl_desc").value = t.description || "";
    document.getElementById("tpl_content").value = t.template || "";
    document.getElementById("tpl_dialog").classList.remove("hidden");
}

async function saveTpl() {
    const body = {
        name: document.getElementById("tpl_name").value,
        category: document.getElementById("tpl_category").value,
        description: document.getElementById("tpl_desc").value,
        template: document.getElementById("tpl_content").value,
    };
    if (!body.name.trim()) { alert("请填写名称"); return; }
    if (editingTplIdx >= 0) {
        await api("PUT", `/api/templates/${editingTplIdx}`, body);
    } else {
        await api("POST", "/api/templates", body);
    }
    templates = await api("GET", "/api/templates");
    renderTemplates();
    closeDialog("tpl_dialog");
}

async function delSelectedTpl() {
    const idxs = getChecked("tpl-check");
    if (!idxs.length) { alert("请先勾选要删除的模板"); return; }
    if (!confirm(`确定删除选中的 ${idxs.length} 个模板?`)) return;
    // 从大到小删,避免索引错位
    for (const i of idxs.sort((a,b)=>b-a)) {
        await api("DELETE", `/api/templates/${i}`);
    }
    templates = await api("GET", "/api/templates");
    renderTemplates();
}

// ============================ 载荷管理 ============================
function renderPayloads() {
    const box = document.getElementById("pld_list");
    box.innerHTML = "";
    payloads.forEach((p, i) => {
        const risk = p.risk_level || "medium";
        const row = document.createElement("div");
        row.className = "list-row";
        row.innerHTML = `
            <input type="checkbox" class="pld-check" data-idx="${i}">
            <span class="row-tag risk-${risk}">[${risk.toUpperCase()}]</span>
            <span class="row-desc">${esc((p.payload||"").slice(0,80))}</span>
            <button class="row-btn" onclick="event.stopPropagation();editPld(${i})">编辑</button>
        `;
        box.appendChild(row);
    });
    document.getElementById("pld_count").textContent = `载荷: ${payloads.length}`;
}

function openPldDialog() {
    editingPldIdx = -1;
    document.getElementById("pld_dialog_title").textContent = "添加测试载荷";
    document.getElementById("pld_content").value = "";
    document.getElementById("pld_risk").value = "medium";
    document.getElementById("pld_dialog").classList.remove("hidden");
}

function editPld(idx) {
    editingPldIdx = idx;
    const p = payloads[idx];
    document.getElementById("pld_dialog_title").textContent = "编辑测试载荷";
    document.getElementById("pld_content").value = p.payload || "";
    document.getElementById("pld_risk").value = p.risk_level || "medium";
    document.getElementById("pld_dialog").classList.remove("hidden");
}

async function savePld() {
    const body = {
        payload: document.getElementById("pld_content").value,
        risk_level: document.getElementById("pld_risk").value,
    };
    if (!body.payload.trim()) { alert("请填写载荷内容"); return; }
    if (editingPldIdx >= 0) {
        await api("PUT", `/api/payloads/${editingPldIdx}`, body);
    } else {
        await api("POST", "/api/payloads", body);
    }
    payloads = await api("GET", "/api/payloads");
    renderPayloads();
    closeDialog("pld_dialog");
}

async function delSelectedPld() {
    const idxs = getChecked("pld-check");
    if (!idxs.length) { alert("请先勾选要删除的载荷"); return; }
    if (!confirm(`确定删除选中的 ${idxs.length} 个载荷?`)) return;
    for (const i of idxs.sort((a,b)=>b-a)) {
        await api("DELETE", `/api/payloads/${i}`);
    }
    payloads = await api("GET", "/api/payloads");
    renderPayloads();
}

// ============================ 自定义输入 ============================
function renderCustomHistory() {
    const box = document.getElementById("custom_history");
    box.innerHTML = "";
    customInputs.forEach(c => {
        const div = document.createElement("div");
        div.className = "history-item";
        div.textContent = `[${c.time || ""}] ${c.content || ""}`;
        box.appendChild(div);
    });
}

async function addCustomInput() {
    const text = document.getElementById("custom_text").value.trim();
    if (!text) { alert("请输入内容"); return; }
    await api("POST", "/api/custom-inputs", { content: text });
    customInputs = await api("GET", "/api/custom-inputs");
    payloads = await api("GET", "/api/payloads");
    renderCustomHistory();
    renderPayloads();
    document.getElementById("custom_text").value = "";
    setStatus("已添加自定义载荷", "#16a34a");
}

async function clearCustomHistory() {
    if (!confirm("确定清除全部历史记录?")) return;
    await api("DELETE", "/api/custom-inputs");
    customInputs = [];
    renderCustomHistory();
}

// ============================ 结果展示 ============================
function renderResults() {
    const body = document.getElementById("res_body");
    body.innerHTML = "";
    results.forEach((r, i) => body.appendChild(buildResultRow(r, i)));
    document.getElementById("res_count").textContent = `结果: ${results.length}`;
    updateStats();
}

// 更新顶部统计概览卡片
function updateStats() {
    const stats = { DANGEROUS_BYPASS: 0, SAFE_BYPASS: 0, BLOCKED: 0, REVIEW: 0 };
    results.forEach(r => { if (stats.hasOwnProperty(r.verdict)) stats[r.verdict]++; });
    document.getElementById("stat_danger").textContent = stats.DANGEROUS_BYPASS;
    document.getElementById("stat_safe").textContent = stats.SAFE_BYPASS;
    document.getElementById("stat_blocked").textContent = stats.BLOCKED;
    document.getElementById("stat_review").textContent = stats.REVIEW;
    document.getElementById("stat_total").textContent = results.length;
}

function buildResultRow(r, i) {
    const tr = document.createElement("tr");
    const v = VERDICT_MAP[r.verdict] || { label: r.verdict, color: "#718096" };
    const resp = (r.response || "").slice(0, 200).replace(/\n/g, " ");
    tr.innerHTML = `
        <td>${esc((r.jailbreak_name||"").slice(0,18))}</td>
        <td>${esc(r.category||"")}</td>
        <td>${esc((r.payload||"").slice(0,60))}</td>
        <td><span class="verdict-tag" style="background:${v.color}">${v.label}</span></td>
        <td class="cell-response">${esc(resp)}</td>
    `;
    tr.addEventListener("click", () => showDetail(r));
    return tr;
}

function showDetail(r) {
    const v = VERDICT_MAP[r.verdict] || { label: r.verdict, color: "#718096" };
    let msgs = "";
    if (r.messages && r.messages.length) {
        msgs = r.messages.map((m, idx) =>
            `--- [${idx+1}] role=${m.role||"?"} ---\n${(m.content||"").slice(0,500)}`
        ).join("\n\n");
    }
    document.getElementById("detail_content").innerHTML = `
        <div class="flex justify-between items-center mb-2">
            <span class="font-bold text-blue-700">模板: ${esc(r.jailbreak_name||"")}</span>
            <span class="verdict-tag" style="background:${v.color}">${v.label}</span>
        </div>
        <div class="detail-section">
            <h4>类别 / 风险</h4>
            <p>${esc(r.category||"")} / ${esc(r.risk_level||"")}</p>
        </div>
        <div class="detail-section">
            <h4>完整请求 (messages)</h4>
            <pre>${esc(msgs || r.prompt || "(无)")}</pre>
        </div>
        <div class="detail-section">
            <h4>模型响应</h4>
            <pre>${esc(r.response || "(无)")}</pre>
        </div>
        <div class="detail-section">
            <h4>判定理由</h4>
            <pre>${esc(r.reason || "(无)")}</pre>
        </div>
    `;
    document.getElementById("detail_dialog").classList.remove("hidden");
}

async function clearResults() {
    if (!confirm("确定清空全部测试结果?")) return;
    await api("DELETE", "/api/results");
    results = [];
    renderResults();
}

// ============================ 模型/连接 ============================
async function testConnection() {
    const url = document.getElementById("target_url").value.trim();
    const key = document.getElementById("target_key").value.trim();
    const el = document.getElementById("conn_status");
    el.textContent = "测试中...";
    const r = await api("POST", "/api/test-connection", { base_url: url, api_key: key });
    el.textContent = r.message || (r.ok ? "成功" : "失败");
    el.style.color = r.ok ? "#16a34a" : "#dc2626";
}

async function fetchModels(which) {
    const urlEl = which === "target"
        ? document.getElementById("target_url")
        : document.getElementById("agent_url");
    const keyEl = which === "target"
        ? document.getElementById("target_key")
        : document.getElementById("agent_key");
    const r = await api("POST", "/api/models", { base_url: urlEl.value.trim(), api_key: keyEl.value.trim() });
    if (r.ok && r.models && r.models.length) {
        MODEL_LISTS[which] = r.models;
        // 自动填充第一个
        const modelEl = which === "target"
            ? document.getElementById("target_model")
            : document.getElementById("agent_model");
        modelEl.value = r.models[0];
        setStatus(`已获取 ${r.models.length} 个模型`, "#16a34a");
    } else {
        MODEL_LISTS[which] = [];
        setStatus(r.message || "获取模型失败", "#dc2626");
    }
}

// ----- 模型选择浮层(替代 datalist,显示全部模型) -----
function openModelPicker(which) {
    modelPickerTarget = which;
    document.getElementById("model_picker_title").textContent =
        (which === "target" ? "选择目标模型" : "选择判定模型");
    document.getElementById("model_search").value = "";
    renderModelList("");
    document.getElementById("model_picker").classList.remove("hidden");
}

function renderModelList(filterText) {
    const box = document.getElementById("model_list_box");
    const models = MODEL_LISTS[modelPickerTarget] || [];
    if (!models.length) {
        box.innerHTML = `<p class="text-slate-400 text-center py-4">暂无模型,请先点"获取模型"</p>`;
        return;
    }
    const ft = filterText.toLowerCase();
    const current = (modelPickerTarget === "target"
        ? document.getElementById("target_model")
        : document.getElementById("agent_model")).value;
    box.innerHTML = models
        .filter(m => !ft || m.toLowerCase().includes(ft))
        .map(m => `<div class="model-item ${m === current ? 'bg-blue-50' : ''}" onclick="selectModel('${esc(m).replace(/'/g, "\\'")}')">${esc(m)}</div>`)
        .join("");
}

function filterModelList() {
    renderModelList(document.getElementById("model_search").value);
}

function selectModel(m) {
    if (modelPickerTarget === "target") {
        document.getElementById("target_model").value = m;
    } else {
        document.getElementById("agent_model").value = m;
    }
    closeDialog("model_picker");
}

// ============================ 评测编排(WebSocket) ============================
function startEvaluate() {
    const tplIdxs = getChecked("tpl-check");
    const pldIdxs = getChecked("pld-check");
    if (!tplIdxs.length) { alert("请至少选择 1 个模板"); return; }
    if (!pldIdxs.length) { alert("请至少勾选 1 个载荷"); return; }

    const useAgent = document.getElementById("use_agent").checked;
    if (useAgent && !document.getElementById("agent_key").value.trim()) {
        alert("启用 Agent 分析需要填写分析 Key");
        return;
    }

    const config = {
        base_url: document.getElementById("target_url").value.trim(),
        api_key: document.getElementById("target_key").value.trim(),
        model_name: document.getElementById("target_model").value.trim(),
        concurrency: parseInt(document.getElementById("concurrency").value) || 3,
        timeout: parseInt(document.getElementById("timeout").value) || 120,
        stream: document.getElementById("use_stream").checked,
        use_agent: useAgent,
        agent_url: document.getElementById("agent_url").value.trim(),
        agent_key: document.getElementById("agent_key").value.trim(),
        agent_model: document.getElementById("agent_model").value.trim(),
        template_idxs: tplIdxs,
        payload_idxs: pldIdxs,
    };

    // 切到结果 Tab,清空旧结果
    switchTab("results");
    results = [];
    renderResults();
    document.getElementById("progress_bar").style.width = "0%";
    document.getElementById("run_btn").disabled = true;
    document.getElementById("stop_btn").disabled = false;
    setStatus("测试中...", "#1d4ed8");

    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws/evaluate`);
    ws.onopen = () => ws.send(JSON.stringify(config));
    ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data);
        handleWsMessage(msg);
    };
    ws.onerror = () => {
        setStatus("连接错误", "#dc2626");
        resetButtons();
    };
    ws.onclose = () => resetButtons();
}

// 流式输出:每个 idx 一行,记录累积文本(支持并发交错)
let streamLines = {};

function handleWsMessage(msg) {
    if (msg.type === "start") {
        setStatus(`测试中... 0/${msg.total}`, "#1d4ed8");
        streamLines = {};
        document.getElementById("stream_box").classList.remove("hidden");
        document.getElementById("stream_content").innerHTML = "";
    } else if (msg.type === "chunk") {
        // 流式 chunk:更新对应 idx 的累积文本行
        streamLines[msg.idx] = { name: msg.jailbreak_name, text: msg.accumulated };
        renderStreamBox();
    } else if (msg.type === "progress") {
        results.push(msg.result);
        document.getElementById("res_body").appendChild(buildResultRow(msg.result, results.length - 1));
        document.getElementById("res_count").textContent = `结果: ${results.length}`;
        updateStats();
        // 该样本已完成,从流式输出区移除
        if (msg.idx !== undefined && streamLines.hasOwnProperty(msg.idx)) {
            delete streamLines[msg.idx];
            renderStreamBox();
        }
        const pct = msg.total ? (msg.done / msg.total * 100) : 0;
        document.getElementById("progress_bar").style.width = pct + "%";
        setStatus(`测试中... ${msg.done}/${msg.total}`, "#1d4ed8");
    } else if (msg.type === "done") {
        const pct = msg.total ? 100 : 0;
        document.getElementById("progress_bar").style.width = pct + "%";
        setStatus(msg.stopped ? `已停止,共 ${msg.count} 条` : `完成: ${msg.count} 条结果`, "#16a34a");
        document.getElementById("stream_box").classList.add("hidden");
        streamLines = {};
        resetButtons();
        // 拉取最终完整结果(确保与服务端一致)
        api("GET", "/api/results").then(r => { results = r; renderResults(); });
    } else if (msg.type === "error") {
        setStatus(msg.message || "错误", "#dc2626");
        alert(msg.message || "评测出错");
        document.getElementById("stream_box").classList.add("hidden");
        resetButtons();
    }
}

function renderStreamBox() {
    const box = document.getElementById("stream_content");
    const lines = Object.values(streamLines);
    if (!lines.length) {
        box.innerHTML = '<span class="text-slate-300">等待模型响应...</span>';
        return;
    }
    box.innerHTML = lines.map(l =>
        `<div class="border-b border-slate-200 py-1"><span class="text-blue-600 font-bold">[${esc(l.name)}]</span> <span class="text-slate-600">${esc(l.text.slice(-200))}</span></div>`
    ).join("");
    // 自动滚到底部
    box.parentElement.scrollTop = box.parentElement.scrollHeight;
}

async function stopEvaluate() {
    await api("POST", "/api/evaluate/stop");
    setStatus("正在停止...", "#d97706");
}

function resetButtons() {
    document.getElementById("run_btn").disabled = false;
    document.getElementById("stop_btn").disabled = true;
}

// ============================ 辅助函数 ============================
function getChecked(cls) {
    return Array.from(document.querySelectorAll(`.${cls}:checked`))
        .map(el => parseInt(el.dataset.idx));
}

function toggleAll(kind, state) {
    const cls = kind === "tpl" ? "tpl-check" : "pld-check";
    document.querySelectorAll(`.${cls}`).forEach(el => el.checked = state);
}

function esc(s) {
    // HTML 转义,防 XSS
    if (s == null) return "";
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
}
