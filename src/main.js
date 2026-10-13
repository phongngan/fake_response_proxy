if (!window.__TAURI__) {
  document.body.insertAdjacentHTML(
    "afterbegin",
    '<div style="background:#900;color:#fff;padding:10px;font:13px monospace">' +
      "window.__TAURI__ is undefined. Open in the Tauri window, not in a browser." +
      "</div>",
  );
  throw new Error("window.__TAURI__ missing");
}
const invoke = window.__TAURI__.core.invoke;

// Thin wrappers over plugin commands so we don't need an npm bundler.
async function dialogOpen(opts = {}) {
  return invoke("plugin:dialog|open", { options: opts });
}
async function dialogSave(opts = {}) {
  return invoke("plugin:dialog|save", { options: opts });
}
async function autostartEnable() {
  return invoke("plugin:autostart|enable");
}
async function autostartDisable() {
  return invoke("plugin:autostart|disable");
}

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  tab: "server",
  status: null,
  config: null,
  rules: [],
  history: [],
  redirect: null, // { install_state, install_dir, windivert_version, rules: [...] }
  rulesFilterListener: "", // "" = all, "<id>" = filter by listener_id, "__global__" = empty listener_id (all-listeners scope)
  probe: null, // { running, target, port, hits: [...] }
  probeForm: { target: "", port: "", include_deleted: false },
};
let _probeTimer = null;

function toast(msg, isErr = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.toggle("err", !!isErr);
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2400);
}

async function refreshStatus() {
  try {
    state.status = await invoke("get_status");
    const running = (state.status.listeners || []).filter((l) => l.state === "running").length;
    const total = (state.status.listeners || []).length;
    const dot = $("#status-dot");
    const lbl = $("#status-label");
    if (dot) dot.classList.toggle("on", running > 0);
    if (lbl) lbl.textContent = `${running}/${total} listening`;
  } catch (e) { /* noop */ }
}

async function refreshConfig() { state.config = await invoke("get_config"); }
async function refreshRules() { state.rules = await invoke("list_rules"); }
async function refreshHistory() { state.history = await invoke("list_history", { limit: 200 }); }

function tabBtns() {
  $$(".tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === state.tab);
    btn.onclick = () => { state.tab = btn.dataset.tab; render(); };
  });
}

async function render() {
  tabBtns();
  await refreshStatus();
  if (state.config === null) await refreshConfig();
  switch (state.tab) {
    case "server": return renderServer();
    case "rules": return renderRules();
    case "redirect": return renderRedirect();
    case "history": return renderHistory();
    case "cert": return renderCert();
    case "settings": return renderSettings();
  }
}

// ---------- SERVER TAB ----------
function renderServer() {
  const s = state.status || {};
  const listeners = s.listeners || [];
  const cfgListeners = state.config?.listeners || [];

  // Show every configured listener; merge with runtime status.
  const merged = cfgListeners.map((c) => {
    const rt = listeners.find((l) => l.id === c.id);
    return {
      id: c.id, scheme: c.scheme, bind: c.bind, port: c.port,
      enabled: c.enabled,
      state: rt?.state || "stopped",
      error: rt?.error || null,
    };
  });

  const rows = merged.map((l) => {
    const stateBadge =
      l.state === "running" ? '<span class="badge green">running</span>'
      : l.state === "failed" ? '<span class="badge red">failed</span>'
      : '<span class="badge">stopped</span>';
    const enabledBadge = l.enabled ? '' : ' <span class="badge">disabled</span>';
    const errLine = l.error ? `<div class="muted" style="font-size:11.5px;color:var(--danger);margin-top:2px">${escapeHtml(l.error)}</div>` : '';
    return `
      <tr data-id="${escapeAttr(l.id)}">
        <td>${stateBadge}${enabledBadge}</td>
        <td>${escapeHtml(l.id)}</td>
        <td><span class="badge ${l.scheme === "https" ? "green" : "blue"}">${l.scheme}</span></td>
        <td class="mono">${escapeHtml(l.bind)}:${l.port}${errLine}</td>
        <td>
          <button class="btn secondary lst-start">Start</button>
          <button class="btn danger lst-stop">Stop</button>
        </td>
      </tr>`;
  }).join("");

  const anyRunning = listeners.some((l) => l.state === "running");
  $("#content").innerHTML = `
    <div class="card">
      <h2>Listeners</h2>
      <div class="desc">Process: ${s.is_elevated ? '<span class="badge green">elevated (admin)</span>' : '<span class="badge">not elevated</span>'} — required for ports &lt;1024.</div>
      <div class="row" style="margin-bottom:10px">
        <button class="btn success" id="btn-start">Start all enabled</button>
        <button class="btn danger" id="btn-stop" ${anyRunning ? "" : "disabled"}>Stop all</button>
        <button class="btn secondary" id="btn-refresh">Refresh</button>
        <span class="muted">Configure listeners in <a href="#" id="goto-settings" style="color:var(--accent)">Settings</a>.</span>
      </div>
      <table>
        <thead><tr>
          <th>State</th><th>ID</th><th>Scheme</th><th>Address</th><th></th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="muted">No listeners configured.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="card">
      <h2>Hosts file integration</h2>
      <div class="desc">Redirect target domains to your bound IP in
        <span class="mono">C:\\Windows\\System32\\drivers\\etc\\hosts</span> (requires admin).
      </div>
      <pre class="raw"># Example
127.0.0.1 telemetry.example.com
127.0.0.1 api.bad-vendor.com</pre>
    </div>
  `;
  $("#btn-start").onclick = async () => {
    try { state.status = await invoke("start_server"); toast("Started"); }
    catch (e) { toast("Start failed: " + e, true); }
    render();
  };
  $("#btn-stop").onclick = async () => {
    try { state.status = await invoke("stop_server"); toast("Stopped"); }
    catch (e) { toast("Stop failed: " + e, true); }
    render();
  };
  $("#btn-refresh").onclick = render;
  $("#goto-settings").onclick = (e) => { e.preventDefault(); state.tab = "settings"; render(); };
  $$("tbody tr").forEach((tr) => {
    const id = tr.dataset.id;
    tr.querySelector(".lst-start").onclick = async () => {
      try { state.status = await invoke("start_listener", { id }); }
      catch (e) { toast("Start failed: " + e, true); }
      render();
    };
    tr.querySelector(".lst-stop").onclick = async () => {
      try { state.status = await invoke("stop_listener", { id }); }
      catch (e) { toast("Stop failed: " + e, true); }
      render();
    };
  });
}

// ---------- RULES TAB ----------
async function renderRules() {
  await Promise.all([refreshRules(), refreshConfig()]);
  const listeners = state.config?.listeners || [];
  const filter = state.rulesFilterListener;

  const matchesFilter = (r) => {
    if (!filter) return true;
    if (filter === "__global__") return !r.listener_id;
    return r.listener_id === filter;
  };
  const visibleRules = state.rules.filter(matchesFilter);

  const listenerLabel = (id) => {
    if (!id) return '<span class="badge blue">all listeners</span>';
    const cfg = listeners.find((l) => l.id === id);
    return cfg
      ? `<span class="badge">${escapeHtml(id)}</span>`
      : `<span class="badge red" title="Listener no longer configured">${escapeHtml(id)} ⚠</span>`;
  };

  // Per-listener rule counts for the filter dropdown.
  const counts = { __all__: state.rules.length, __global__: state.rules.filter((r) => !r.listener_id).length };
  for (const l of listeners) counts[l.id] = state.rules.filter((r) => r.listener_id === l.id).length;

  const filterOptions = [
    `<option value="">All (${counts.__all__})</option>`,
    `<option value="__global__" ${filter === "__global__" ? "selected" : ""}>(applies to all listeners) — ${counts.__global__}</option>`,
    ...listeners.map(
      (l) =>
        `<option value="${escapeAttr(l.id)}" ${filter === l.id ? "selected" : ""}>${escapeHtml(l.id)} — ${counts[l.id] || 0}</option>`,
    ),
  ].join("");

  const rows = visibleRules.map((r) => {
    const defaultBadge = r.is_default ? ' <span class="badge red">DEFAULT</span>' : "";
    const matchHost = r.is_default ? '<span class="muted">—</span>' : escapeHtml(r.host || "*");
    const matchMethod = r.is_default ? '<span class="muted">—</span>' : escapeHtml(r.method || "*");
    const matchPath = r.is_default ? '<span class="muted">—</span>' : escapeHtml(r.path_regex || ".*");
    return `
    <tr data-id="${r.id}">
      <td>${r.enabled ? '<span class="badge green">on</span>' : '<span class="badge">off</span>'}${defaultBadge}</td>
      <td>${escapeHtml(r.name)}</td>
      <td>${listenerLabel(r.listener_id || "")}</td>
      <td class="mono">${matchHost}</td>
      <td class="mono">${matchMethod}</td>
      <td class="mono">${matchPath}</td>
      <td><span class="badge blue">${r.response.kind}</span></td>
      <td><button class="btn secondary edit">Edit</button> <button class="btn danger del">Del</button></td>
    </tr>`;
  }).join("");
  $("#content").innerHTML = `
    <div class="card">
      <h2>Response rules</h2>
      <div class="desc">First enabled rule that matches Listener + Host + Method + path-regex wins.
        Rules scoped to "all listeners" act as fallbacks across every listener.</div>
      <div class="row" style="margin-bottom:10px">
        <button class="btn" id="btn-new">+ New rule</button>
        <label class="muted" style="display:flex;align-items:center;gap:6px">
          Filter listener
          <select id="rules-filter">${filterOptions}</select>
        </label>
      </div>
      <table>
        <thead><tr>
          <th>Status</th><th>Name</th><th>Listener</th><th>Host</th><th>Method</th><th>Path regex</th><th>Source</th><th></th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="muted">No rules match the current filter.</td></tr>'}</tbody>
      </table>
    </div>
  `;
  $("#btn-new").onclick = () => openRuleEditor(null);
  $("#rules-filter").onchange = (e) => {
    state.rulesFilterListener = e.target.value;
    render();
  };
  $$("tbody tr").forEach((tr) => {
    const id = parseInt(tr.dataset.id, 10);
    const rule = state.rules.find((r) => r.id === id);
    const edit = tr.querySelector(".edit");
    const del = tr.querySelector(".del");
    if (edit) edit.onclick = (e) => { e.stopPropagation(); openRuleEditor(rule); };
    if (del) del.onclick = async (e) => {
      e.stopPropagation();
      if (!confirm("Delete rule?")) return;
      try { await invoke("delete_rule", { id }); toast("Deleted"); render(); }
      catch (e) { toast("Delete failed: " + e, true); }
    };
  });
}

function openRuleEditor(rule) {
  const isNew = !rule;
  // Pre-fill listener if the user is filtering by a specific listener.
  const presetListener =
    state.rulesFilterListener && state.rulesFilterListener !== "__global__"
      ? state.rulesFilterListener
      : "";
  const r = rule || {
    id: 0, name: "New rule", enabled: true,
    listener_id: presetListener,
    is_default: false,
    host: "", method: "", path_regex: "",
    response: { kind: "none" },
  };
  const kind = r.response.kind || "none";
  const listeners = state.config?.listeners || [];
  const listenerOpts = [
    `<option value="" ${!r.listener_id ? "selected" : ""}>(all listeners)</option>`,
    ...listeners.map(
      (l) =>
        `<option value="${escapeAttr(l.id)}" ${r.listener_id === l.id ? "selected" : ""}>${escapeHtml(l.id)} — ${escapeHtml(l.scheme)} ${escapeHtml(l.bind)}:${l.port}</option>`,
    ),
  ];
  // If rule's listener_id refers to a deleted listener, add a "stale" option.
  if (r.listener_id && !listeners.some((l) => l.id === r.listener_id)) {
    listenerOpts.push(
      `<option value="${escapeAttr(r.listener_id)}" selected>${escapeHtml(r.listener_id)} (stale — listener removed)</option>`,
    );
  }
  const html = `
    <div class="modal-backdrop">
      <div class="modal">
        <header>
          <strong>${isNew ? "New rule" : "Edit rule #" + r.id}</strong>
          <button class="btn secondary" id="m-close">Close</button>
        </header>
        <div class="body">
          <div class="split">
            <label>Name <input id="r-name" type="text" value="${escapeAttr(r.name)}"/></label>
            <label class="inline"><input id="r-enabled" type="checkbox" ${r.enabled ? "checked" : ""}/> Enabled</label>
            <label style="grid-column:1/-1">Listener (which proxy this rule applies to)
              <select id="r-listener">${listenerOpts.join("")}</select>
            </label>
            <label class="inline" style="grid-column:1/-1">
              <input id="r-default" type="checkbox" ${r.is_default ? "checked" : ""}/>
              Default rule — applied as fallback when no other rule matches (host/method/path ignored)
            </label>
            <label>Host (exact, empty = any) <input id="r-host" type="text" value="${escapeAttr(r.host)}"/></label>
            <label>Method (e.g. GET, empty = any) <input id="r-method" type="text" value="${escapeAttr(r.method)}"/></label>
            <label style="grid-column:1/-1">Path regex (matches path+query, empty = any) <input id="r-path" type="text" value="${escapeAttr(r.path_regex)}"/></label>
          </div>
          <hr style="border-color:var(--border); margin:14px 0"/>
          <label>Response source
            <select id="r-kind">
              <option value="none" ${kind==="none"?"selected":""}>none (404)</option>
              <option value="raw_text" ${kind==="raw_text"?"selected":""}>raw text</option>
              <option value="file" ${kind==="file"?"selected":""}>file path</option>
              <option value="script" ${kind==="script"?"selected":""}>python script</option>
              <option value="forward" ${kind==="forward"?"selected":""}>forward to ip:port (e.g. Burp Suite)</option>
            </select>
          </label>
          <div id="r-source-pane" style="margin-top:10px"></div>
        </div>
        <footer>
          <button class="btn secondary" id="m-cancel">Cancel</button>
          <button class="btn" id="m-save">Save</button>
        </footer>
      </div>
    </div>`;
  const wrap = document.createElement("div");
  wrap.innerHTML = html;
  document.body.appendChild(wrap);
  const close = () => wrap.remove();
  wrap.querySelector("#m-close").onclick = close;
  wrap.querySelector("#m-cancel").onclick = close;

  const renderSourcePane = () => {
    const k = wrap.querySelector("#r-kind").value;
    const pane = wrap.querySelector("#r-source-pane");
    if (k === "none") {
      pane.innerHTML = `<div class="muted">No response — a 404 will be returned.</div>`;
    } else if (k === "raw_text") {
      pane.innerHTML = `
        <label>Raw HTTP response (paste full raw message)
          <textarea id="r-raw" spellcheck="false">${escapeHtml(r.response.raw || defaultRaw())}</textarea>
        </label>`;
    } else if (k === "file") {
      pane.innerHTML = `
        <label>Path to raw HTTP response file
          <div class="row">
            <input id="r-file" type="text" style="flex:1" value="${escapeAttr(r.response.path || "")}"/>
            <button class="btn secondary" id="r-pick">Browse...</button>
          </div>
        </label>`;
      wrap.querySelector("#r-pick").onclick = async () => {
        const p = await dialogOpen({ multiple: false });
        if (p) wrap.querySelector("#r-file").value = p;
      };
    } else if (k === "script") {
      pane.innerHTML = `
        <label>Python interpreter (empty = "python")
          <input id="r-python" type="text" value="${escapeAttr(r.response.python || "")}"/>
        </label>
        <label style="margin-top:8px">Path to .py script
          <div class="row">
            <input id="r-script" type="text" style="flex:1" value="${escapeAttr(r.response.script || "")}"/>
            <button class="btn secondary" id="r-pick">Browse...</button>
          </div>
        </label>
        <label style="margin-top:8px">Extra args (comma-separated, optional)
          <input id="r-args" type="text" value="${escapeAttr((r.response.args || []).join(","))}"/>
        </label>
        <div class="desc" style="margin-top:8px">The script is called as:
          <span class="mono">python &lt;script&gt; [args...] &lt;request_temp_file&gt;</span>.
          It must print the path of the response file to stdout. Both files are deleted after.
        </div>`;
      wrap.querySelector("#r-pick").onclick = async () => {
        const p = await dialogOpen({ multiple: false, filters: [{ name: "Python", extensions: ["py"] }] });
        if (p) wrap.querySelector("#r-script").value = p;
      };
    } else if (k === "forward") {
      const tls = (r.response.tls || "auto");
      pane.innerHTML = `
        <label>Forward target <span class="mono">host:port</span>
          <input id="r-fwd-target" type="text" value="${escapeAttr(r.response.target || "127.0.0.1:8080")}" placeholder="127.0.0.1:8080"/>
        </label>
        <label style="margin-top:8px">TLS to target
          <select id="r-fwd-tls">
            <option value="auto" ${tls==="auto"?"selected":""}>auto — mirror inbound (HTTPS→TLS, HTTP→plain)</option>
            <option value="off" ${tls==="off"?"selected":""}>off — always plain HTTP</option>
            <option value="on" ${tls==="on"?"selected":""}>on — always TLS (SNI = original Host)</option>
          </select>
        </label>
        <label class="inline" style="margin-top:8px">
          <input id="r-fwd-proxy" type="checkbox" ${r.response.proxy_style ? "checked" : ""}/>
          Send as HTTP proxy request (absolute-form URI — use when target is an explicit HTTP proxy, not Burp invisible mode)
        </label>
        <div class="desc" style="margin-top:8px">The matched request is relayed to the target and the upstream response is
          sent back to the client. With <strong>auto</strong>, HTTPS requests reach Burp as HTTPS (Burp mints a leaf cert per SNI;
          our client skips cert verification). For Burp, enable "Support invisible proxying" on the listener (Request handling tab).
        </div>`;
    }
  };
  renderSourcePane();
  wrap.querySelector("#r-kind").onchange = renderSourcePane;

  wrap.querySelector("#m-save").onclick = async () => {
    const k = wrap.querySelector("#r-kind").value;
    let response = { kind: "none" };
    if (k === "raw_text") {
      response = { kind: "raw_text", raw: wrap.querySelector("#r-raw").value };
    } else if (k === "file") {
      response = { kind: "file", path: wrap.querySelector("#r-file").value };
    } else if (k === "script") {
      const argsStr = wrap.querySelector("#r-args").value.trim();
      response = {
        kind: "script",
        python: wrap.querySelector("#r-python").value || null,
        script: wrap.querySelector("#r-script").value,
        args: argsStr ? argsStr.split(",").map((s) => s.trim()).filter(Boolean) : [],
      };
    } else if (k === "forward") {
      response = {
        kind: "forward",
        target: wrap.querySelector("#r-fwd-target").value.trim(),
        proxy_style: wrap.querySelector("#r-fwd-proxy").checked,
        tls: wrap.querySelector("#r-fwd-tls").value,
      };
    }
    const payload = {
      id: r.id || 0,
      name: wrap.querySelector("#r-name").value || "Unnamed",
      enabled: wrap.querySelector("#r-enabled").checked,
      listener_id: wrap.querySelector("#r-listener").value,
      is_default: wrap.querySelector("#r-default").checked,
      host: wrap.querySelector("#r-host").value.trim(),
      method: wrap.querySelector("#r-method").value.trim(),
      path_regex: wrap.querySelector("#r-path").value.trim(),
      response,
    };
    try { await invoke("upsert_rule", { rule: payload }); toast("Saved"); close(); render(); }
    catch (e) { toast("Save failed: " + e, true); }
  };
}

function defaultRaw() {
  const body = '{"ok":true}';
  return `HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n${body}`;
}

// ---------- REDIRECT TAB ----------
async function refreshRedirect() {
  try { state.redirect = await invoke("get_redirect_status"); }
  catch { state.redirect = null; }
}

async function refreshProbe() {
  try { state.probe = await invoke("probe_status"); }
  catch { state.probe = null; }
}

async function renderRedirect() {
  await Promise.all([refreshRedirect(), refreshConfig(), refreshProbe()]);
  const r = state.redirect || { install_state: "missing", install_dir: "", windivert_version: "?", rules: [] };
  const rules = state.config?.redirects || [];
  const elevated = !!(state.status && state.status.is_elevated);

  const installBadge = ({
    installed: '<span class="badge green">installed</span>',
    missing:   '<span class="badge">not installed</span>',
    downloading: '<span class="badge blue">downloading…</span>',
    failed:    '<span class="badge red">failed</span>',
  })[r.install_state] || '';
  const elevBadge = elevated
    ? '<span class="badge green">elevated (admin)</span>'
    : '<span class="badge red">not elevated — required for redirect</span>';

  const rtMap = new Map((r.rules || []).map((x) => [x.id, x]));
  const rows = rules.map((rule) => {
    const rt = rtMap.get(rule.id);
    const stateBadge = rt
      ? (rt.state === "running" ? '<span class="badge green">running</span>'
         : rt.state === "failed" ? '<span class="badge red">failed</span>'
         : '<span class="badge">stopped</span>')
      : '<span class="badge">stopped</span>';
    const enabledBadge = rule.enabled ? '' : ' <span class="badge">disabled</span>';
    const procBadge = rule.process
      ? `<span class="badge">${escapeHtml(rule.process)}</span>`
      : '<span class="badge blue">all processes</span>';
    const portLabel = rule.target_port ? `:${rule.target_port}` : "";
    const targetLabel = rule.target?.trim()
      ? `${escapeHtml(rule.target)}${portLabel}`
      : `<span class="muted">any</span>${portLabel}`;
    const resolved = (rt && rt.resolved_targets && rt.resolved_targets.length)
      ? `<div class="muted" style="font-size:11.5px">→ ${rt.resolved_targets.map(escapeHtml).join(", ")}</div>`
      : '';
    const redirIp = rule.redirect_to_ip || "10.66.66.x";
    const stats = rt
      ? `<span class="muted" style="font-size:11.5px">active=${rt.active_connections} pkts=${rt.forwarded_packets}</span>`
      : '';
    const startDisabled = (elevated && r.install_state === "installed") ? '' : 'disabled';
    return `
      <tr data-id="${escapeAttr(rule.id)}">
        <td>${stateBadge}${enabledBadge}</td>
        <td>${escapeHtml(rule.name)}</td>
        <td class="mono">${targetLabel}${resolved}</td>
        <td class="mono">${escapeHtml(redirIp)}:${rule.listen_port}</td>
        <td>${procBadge}</td>
        <td>${stats}</td>
        <td>
          <button class="btn secondary rd-start" ${startDisabled}>Start</button>
          <button class="btn danger rd-stop">Stop</button>
          <button class="btn secondary rd-edit">Edit</button>
          <button class="btn danger rd-del">Del</button>
        </td>
      </tr>`;
  }).join("");

  $("#content").innerHTML = `
    <div class="card">
      <h2>WinDivert (TCP redirect)</h2>
      <div class="desc">Redirect outbound TCP connections to a local proxy port without binding the
        original port and without editing the hosts file. Works even when the source app uses a hard-coded IP.</div>
      <div class="kv">
        <div>Driver</div><div>${installBadge} <span class="muted">v${escapeHtml(r.windivert_version)}</span></div>
        <div>Install dir</div><div class="mono">${escapeHtml(r.install_dir)}</div>
        <div>Process</div><div>${elevBadge}</div>
      </div>
      <div class="row" style="margin-top:12px">
        ${r.install_state !== "installed" ? `<button class="btn" id="btn-install-wd" ${elevated ? "" : "disabled"}>Install WinDivert now</button>` : ''}
        ${elevated ? '' : '<button class="btn" id="btn-uac">Restart as Administrator</button>'}
        <button class="btn secondary" id="btn-rd-refresh">Refresh</button>
      </div>
    </div>
    <div class="card">
      <h2>Redirect rules</h2>
      <div class="desc">Each rule intercepts outbound TCP to <span class="mono">target_port</span> and forwards it to
        <span class="mono">redirect_to_ip:listen_port</span>. Make sure a local listener is running on that address in the Server tab.<br>
        <strong style="color:var(--warn)">Note:</strong> redirecting to <span class="mono">127.0.0.1</span> often fails silently on Windows
        (TCP stack anti-spoofing on loopback). Use the machine's LAN IP (e.g. <span class="mono">10.x.y.z</span> from <span class="mono">ipconfig</span>)
        and bind the listener to <span class="mono">0.0.0.0:&lt;port&gt;</span>.</div>
      <div class="row" style="margin-bottom:10px">
        <button class="btn" id="btn-rd-new">+ New redirect rule</button>
      </div>
      <table>
        <thead><tr>
          <th>State</th><th>Name</th><th>Match (dst)</th><th>Redirect to</th><th>Scope</th><th></th><th></th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="muted">No redirect rules yet.</td></tr>'}</tbody>
      </table>
    </div>
    ${renderProbeCard(elevated)}
  `;

  bindProbeCard();

  const installBtn = $("#btn-install-wd");
  if (installBtn) installBtn.onclick = async () => {
    installBtn.disabled = true; installBtn.textContent = "Downloading…";
    try { await invoke("install_windivert"); toast("WinDivert installed"); }
    catch (e) { toast("Install failed: " + e, true); }
    render();
  };
  const uacBtn = $("#btn-uac");
  if (uacBtn) uacBtn.onclick = async () => {
    if (!confirm("Relaunch the app as Administrator? Current window will close.")) return;
    try { await invoke("request_admin_relaunch"); }
    catch (e) { toast("Relaunch failed: " + e, true); }
  };
  $("#btn-rd-refresh").onclick = render;
  $("#btn-rd-new").onclick = () => openRedirectEditor(null);

  $$("tbody tr").forEach((tr) => {
    const id = tr.dataset.id;
    if (!id) return;
    const rule = rules.find((x) => x.id === id);
    const start = tr.querySelector(".rd-start");
    const stop = tr.querySelector(".rd-stop");
    const edit = tr.querySelector(".rd-edit");
    const del = tr.querySelector(".rd-del");
    if (start) start.onclick = async () => {
      try { await invoke("start_redirect_rule", { id }); toast("Started"); }
      catch (e) { toast("Start failed: " + e, true); }
      render();
    };
    if (stop) stop.onclick = async () => {
      try { await invoke("stop_redirect_rule", { id }); toast("Stopped"); }
      catch (e) { toast("Stop failed: " + e, true); }
      render();
    };
    if (edit) edit.onclick = () => openRedirectEditor(rule);
    if (del) del.onclick = async () => {
      if (!confirm(`Delete redirect rule "${rule.name}"?`)) return;
      try { await invoke("delete_redirect_rule", { id }); toast("Deleted"); render(); }
      catch (e) { toast("Delete failed: " + e, true); }
    };
  });
}

function renderProbeCard(elevated) {
  const p = state.probe || { running: false, hits: [], resolved_targets: [], filter: "" };
  const form = state.probeForm;
  const running = !!p.running;
  // If running, prefer the live target/port over the form draft.
  const targetVal = running ? (p.target || "") : (form.target || "");
  const portVal = running ? (p.port ?? "") : (form.port || "");
  const includeDeleted = running ? p.include_deleted : !!form.include_deleted;

  const resolvedNote = (running && p.resolved_targets && p.resolved_targets.length)
    ? `<div class="muted" style="font-size:11.5px">Resolved: ${p.resolved_targets.map(escapeHtml).join(", ")}</div>`
    : "";
  const filterNote = (running && p.filter)
    ? `<div class="muted mono" style="font-size:11px">filter: ${escapeHtml(p.filter)}</div>`
    : "";

  // Aggregate per-process counts.
  const counts = new Map();
  for (const h of p.hits || []) {
    const k = h.process_name + " (" + h.pid + ")";
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const summary = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([k, n]) => `<span class="badge">${escapeHtml(k)} × ${n}</span>`)
    .join(" ");

  const rows = (p.hits || []).slice().reverse().slice(0, 200).map((h) => `
    <tr>
      <td class="mono">${new Date(h.ts).toLocaleTimeString()}</td>
      <td>${h.event === "established" ? '<span class="badge green">est</span>' : '<span class="badge">del</span>'}</td>
      <td>${escapeHtml(h.process_name)}</td>
      <td class="mono">${h.pid}</td>
      <td class="mono">${escapeHtml(h.local_addr)}:${h.local_port}</td>
      <td class="mono">${escapeHtml(h.remote_addr)}:${h.remote_port}</td>
    </tr>`).join("");

  const startDisabled = (elevated && (state.redirect?.install_state === "installed")) ? "" : "disabled";

  return `
    <div class="card">
      <h2>Process finder</h2>
      <div class="desc">Passively log which processes connect to a target. Useful to discover the right
        <span class="mono">process</span> value for a redirect rule when an app uses background helpers
        instead of the obvious binary. Uses WinDivert FLOW layer (sniff-only, no rewrite).</div>
      <div class="split" style="gap:8px">
        <label>Target host / IP (comma-separated, empty = any)
          <input id="pb-target" type="text" value="${escapeAttr(targetVal)}" ${running ? "disabled" : ""} placeholder="bmtrading.de, 85.13.135.81"/>
        </label>
        <label>Remote port (empty = any)
          <input id="pb-port" type="number" min="0" max="65535" value="${escapeAttr(String(portVal))}" ${running ? "disabled" : ""} placeholder="443"/>
        </label>
        <label class="inline" style="grid-column:1/-1">
          <input id="pb-deleted" type="checkbox" ${includeDeleted ? "checked" : ""} ${running ? "disabled" : ""}/>
          Also log FLOW_DELETED events (verbose — shows connection close too)
        </label>
      </div>
      ${resolvedNote}${filterNote}
      <div class="row" style="margin-top:10px">
        ${running
          ? `<button class="btn danger" id="pb-stop">Stop probe</button>`
          : `<button class="btn success" id="pb-start" ${startDisabled}>Start probe</button>`}
        <button class="btn secondary" id="pb-clear">Clear hits</button>
        <span class="muted">${(p.hits || []).length} hits (cap 500). Auto-refresh every 1.5s while running.</span>
      </div>
      ${summary ? `<div class="row" style="flex-wrap:wrap;gap:6px;margin-top:10px">${summary}</div>` : ""}
      <table style="margin-top:10px">
        <thead><tr>
          <th>Time</th><th>Event</th><th>Process</th><th>PID</th><th>Local</th><th>Remote</th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="muted">No hits yet. Start a probe and then trigger traffic in the target app.</td></tr>'}</tbody>
      </table>
    </div>
  `;
}

function bindProbeCard() {
  const startBtn = $("#pb-start");
  const stopBtn = $("#pb-stop");
  const clearBtn = $("#pb-clear");

  if (startBtn) startBtn.onclick = async () => {
    const target = $("#pb-target").value.trim();
    const portRaw = $("#pb-port").value.trim();
    const includeDeleted = $("#pb-deleted").checked;
    state.probeForm = { target, port: portRaw, include_deleted: includeDeleted };
    const req = {
      target,
      port: portRaw ? (parseInt(portRaw, 10) || null) : null,
      include_deleted: includeDeleted,
    };
    try {
      await invoke("start_probe", { request: req });
      toast("Probe started");
      ensureProbeTimer();
    } catch (e) { toast("Probe failed: " + e, true); }
    render();
  };
  if (stopBtn) stopBtn.onclick = async () => {
    try { await invoke("stop_probe"); toast("Probe stopped"); }
    catch (e) { toast("Stop failed: " + e, true); }
    clearProbeTimer();
    render();
  };
  if (clearBtn) clearBtn.onclick = async () => {
    try { await invoke("clear_probe_hits"); }
    catch (e) { toast("Clear failed: " + e, true); }
    render();
  };

  if (state.probe?.running) ensureProbeTimer();
  else clearProbeTimer();
}

function ensureProbeTimer() {
  if (_probeTimer) return;
  _probeTimer = setInterval(async () => {
    if (state.tab !== "redirect") return;
    if (!state.probe?.running) { clearProbeTimer(); return; }
    try {
      state.probe = await invoke("probe_status");
      // Surgical update: replace only the Process finder card to avoid
      // tearing down the rest of the tab on every tick.
      const cards = $$("#content > .card");
      const probeCard = cards[cards.length - 1];
      if (probeCard) {
        const elevated = !!(state.status && state.status.is_elevated);
        const tmp = document.createElement("div");
        tmp.innerHTML = renderProbeCard(elevated);
        probeCard.replaceWith(tmp.firstElementChild);
        bindProbeCard();
      }
    } catch {}
  }, 1500);
}

function clearProbeTimer() {
  if (_probeTimer) { clearInterval(_probeTimer); _probeTimer = null; }
}

function openRedirectEditor(rule) {
  const isNew = !rule;
  const r = rule || {
    id: "",
    name: "New redirect",
    enabled: false,
    target: "",
    target_port: 443,
    listen_port: 18443,
    redirect_to_ip: "10.66.66.x",
    process: null,
  };
  const wrap = document.createElement("div");
  wrap.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <header>
          <strong>${isNew ? "New redirect rule" : "Edit redirect: " + escapeHtml(r.name)}</strong>
          <button class="btn secondary" id="m-close">Close</button>
        </header>
        <div class="body">
          <div class="split">
            <label>Name <input id="rd-name" type="text" value="${escapeAttr(r.name)}"/></label>
            <label class="inline"><input id="rd-enabled" type="checkbox" ${r.enabled ? "checked" : ""}/> Enabled (auto-start)</label>
            <label style="grid-column:1/-1">Match destination — IPv4 or hostname, comma-separated (empty = any IP)
              <input id="rd-targethost" type="text" value="${escapeAttr(r.target || "")}" placeholder="evil.example.com, 1.2.3.4"/></label>
            <label>Match destination port (0 = any)
              <input id="rd-target" type="number" min="0" max="65535" value="${r.target_port ?? 443}"/></label>
            <label>Redirect to IP (không được dùng 127.0.0.1 loopback sẽ bị drop, dùng ip private hoặc public)
              <input id="rd-redir-ip" type="text" value="${escapeAttr(r.redirect_to_ip || "10.66.66.x")}" placeholder="10.66.66.19"/></label>
            <label>Redirect to port (where your proxy listens)
              <input id="rd-listen" type="number" min="1" max="65535" value="${r.listen_port}"/></label>
            <label style="grid-column:1/-1">Process name (optional — e.g. <span class="mono">target.exe</span>, empty = all processes)
              <input id="rd-process" type="text" value="${escapeAttr(r.process || "")}" placeholder="leave empty for all processes"/></label>
          </div>
          <div class="desc" style="margin-top:10px">
            Hostnames are resolved when the rule starts. To match the source app regardless of
            whether it connects by IP or hostname, list both (e.g. <span class="mono">evil.example.com, 1.2.3.4</span>).
            Use <span class="mono">127.0.0.1</span> for a local proxy, or any IP for a remote one.
            Requires Administrator + WinDivert installed.
          </div>
        </div>
        <footer>
          <button class="btn secondary" id="m-cancel">Cancel</button>
          <button class="btn" id="m-save">Save</button>
        </footer>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  const close = () => wrap.remove();
  wrap.querySelector("#m-close").onclick = close;
  wrap.querySelector("#m-cancel").onclick = close;
  wrap.querySelector("#m-save").onclick = async () => {
    const id = r.id || ("redir-" + Math.random().toString(16).slice(2, 10));
    const procRaw = wrap.querySelector("#rd-process").value.trim();
    const payload = {
      id,
      name: wrap.querySelector("#rd-name").value || "Unnamed",
      enabled: wrap.querySelector("#rd-enabled").checked,
      target: wrap.querySelector("#rd-targethost").value.trim(),
      target_port: parseInt(wrap.querySelector("#rd-target").value, 10) || 0,
      listen_port: parseInt(wrap.querySelector("#rd-listen").value, 10) || 18443,
      redirect_to_ip: wrap.querySelector("#rd-redir-ip").value.trim() || "10.66.66.x",
      process: procRaw || null,
    };
    try {
      await invoke("upsert_redirect_rule", { rule: payload });
      if (payload.enabled) {
        try { await invoke("start_redirect_rule", { id }); }
        catch (e) { toast("Saved, start failed: " + e, true); }
      } else {
        try { await invoke("stop_redirect_rule", { id }); } catch {}
      }
      toast("Saved");
      close();
      render();
    } catch (e) { toast("Save failed: " + e, true); }
  };
}

// ---------- HISTORY TAB ----------
async function renderHistory() {
  await refreshHistory();
  const rows = state.history.map((h) => `
    <tr data-id="${h.id}" ${h.has_full ? '' : 'class="muted"'}>
      <td class="mono">${new Date(h.ts).toLocaleTimeString()}</td>
      <td class="mono">${h.listener_id ? `<span class="badge">${escapeHtml(h.listener_id)}</span>` : '<span class="muted">—</span>'}</td>
      <td><span class="badge ${h.scheme === "https" ? "green" : "blue"}">${h.scheme}</span></td>
      <td class="mono">${h.method}</td>
      <td class="mono">${escapeHtml(h.host)}</td>
      <td class="mono" style="max-width:340px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(h.path)}</td>
      <td><span class="badge ${h.status < 300 ? "green" : h.status < 500 ? "blue" : "red"}">${h.status}</span></td>
      <td>${escapeHtml(h.source)}${h.rule_id ? ` #${h.rule_id}` : ""}</td>
      <td>${h.duration_ms}ms</td>
    </tr>`).join("");
  $("#content").innerHTML = `
    <div class="card">
      <h2>Request history</h2>
      <div class="row" style="margin-bottom:10px">
        <button class="btn secondary" id="btn-refresh">Refresh</button>
        <button class="btn danger" id="btn-clear">Clear all</button>
        <span class="muted">Last ${state.history.length} (max 1000); full body kept for last 100.</span>
      </div>
      <table>
        <thead><tr>
          <th>Time</th><th>Listener</th><th>Scheme</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Source</th><th>Dur</th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="9" class="muted">No requests yet.</td></tr>'}</tbody>
      </table>
    </div>
  `;
  $("#btn-refresh").onclick = render;
  $("#btn-clear").onclick = async () => {
    if (!confirm("Clear all history?")) return;
    await invoke("clear_history");
    render();
  };
  $$("tbody tr").forEach((tr) => {
    tr.onclick = async () => {
      const id = parseInt(tr.dataset.id, 10);
      const msg = await invoke("get_full_message", { requestId: id });
      if (!msg) { toast("Full message not stored for this entry"); return; }
      openFullViewer(msg);
    };
  });
}

function openFullViewer(msg) {
  const wrap = document.createElement("div");
  wrap.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <header>
          <strong>Request #${msg.request_id} — ${new Date(msg.ts).toLocaleString()}</strong>
          <button class="btn secondary" id="m-close">Close</button>
        </header>
        <div class="body">
          <h3 style="margin:0 0 6px">Request</h3>
          <pre class="raw">${escapeHtml(msg.request_raw)}</pre>
          <h3 style="margin:14px 0 6px">Response</h3>
          <pre class="raw">${escapeHtml(msg.response_raw)}</pre>
        </div>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  wrap.querySelector("#m-close").onclick = () => wrap.remove();
}

// ---------- CERT TAB ----------
async function renderCert() {
  const s = state.status || {};
  // Render skeleton immediately, then enrich with install state (slow).
  const skeleton = (caState) => {
    const userBadge = caState
      ? (caState.installed_user ? '<span class="badge green">installed</span>' : '<span class="badge">not installed</span>')
      : '<span class="muted">checking…</span>';
    const sysBadge = caState
      ? (caState.installed_system ? '<span class="badge green">installed</span>' : '<span class="badge">not installed</span>')
      : '<span class="muted">checking…</span>';
    const thumb = caState?.thumbprint
      ? `<span class="mono" title="SHA-1 fingerprint">${caState.thumbprint.match(/.{1,4}/g).join(" ")}</span>`
      : '<span class="muted">…</span>';
    const cn = caState?.common_name || "Fake Response Proxy Root CA";
    return `
    <div class="card">
      <h2>Root CA</h2>
      <div class="desc">A self-signed root CA is generated on first run. Install it into your
        trust store so HTTPS clients trust the leaf certs we generate per domain.</div>
      <div class="kv">
        <div>Common name</div><div class="mono">${escapeHtml(cn)}</div>
        <div>SHA-1 thumbprint</div><div>${thumb}</div>
        <div>PEM path</div><div class="mono">${escapeHtml(s.ca_cert_path || "")}</div>
        <div>Current user trust</div><div>${userBadge}</div>
        <div>Local machine trust</div><div>${sysBadge} ${s.is_elevated ? '' : '<span class="muted">(admin needed to modify)</span>'}</div>
        <div>Elevation</div><div>${s.is_elevated ? '<span class="badge green">admin</span>' : '<span class="badge">not admin (system install disabled)</span>'}</div>
      </div>
      <div class="row" style="margin-top:12px">
        <button class="btn" id="btn-install-user" ${caState?.installed_user ? 'disabled' : ''}>Install (current user)</button>
        <button class="btn" id="btn-install-sys" ${(s.is_elevated && !caState?.installed_system) ? "" : "disabled"}>Install (system, requires admin)</button>
        <button class="btn secondary" id="btn-uninstall-user" ${caState?.installed_user ? '' : 'disabled'}>Uninstall (user)</button>
        <button class="btn secondary" id="btn-uninstall-sys" ${(s.is_elevated && caState?.installed_system) ? "" : "disabled"}>Uninstall (system)</button>
        <button class="btn secondary" id="btn-export">Copy PEM to clipboard</button>
        <button class="btn secondary" id="btn-cert-refresh">Refresh</button>
      </div>
    </div>
  `;
  };

  $("#content").innerHTML = skeleton(null);
  let caState = null;
  try { caState = await invoke("get_ca_install_state"); }
  catch (e) { /* keep skeleton */ }
  $("#content").innerHTML = skeleton(caState);

  const handle = async (cmd, args, ok) => {
    try { const m = await invoke(cmd, args); toast(ok || m || "done"); render(); }
    catch (e) { toast("Error: " + e, true); }
  };
  $("#btn-install-user").onclick = () => handle("install_ca", { systemWide: false });
  $("#btn-install-sys").onclick = () => handle("install_ca", { systemWide: true });
  $("#btn-uninstall-user").onclick = () => handle("uninstall_ca", { systemWide: false });
  $("#btn-uninstall-sys").onclick = () => handle("uninstall_ca", { systemWide: true });
  $("#btn-cert-refresh").onclick = render;
  $("#btn-export").onclick = async () => {
    try {
      const pem = await invoke("export_ca");
      await navigator.clipboard.writeText(pem);
      toast("Root CA PEM copied to clipboard");
    } catch (e) { toast("Copy failed: " + e, true); }
  };
}

// ---------- SETTINGS TAB ----------
function renderSettings() {
  const c = state.config;
  const listeners = c.listeners || [];

  const rows = listeners.map((l, i) => `
    <tr data-i="${i}">
      <td><input type="checkbox" class="l-en" ${l.enabled ? "checked" : ""}/></td>
      <td><input type="text" class="l-id" value="${escapeAttr(l.id)}" style="width:120px"/></td>
      <td>
        <select class="l-scheme">
          <option value="http" ${l.scheme === "http" ? "selected" : ""}>http</option>
          <option value="https" ${l.scheme === "https" ? "selected" : ""}>https</option>
        </select>
      </td>
      <td><input type="text" class="l-bind" value="${escapeAttr(l.bind)}" style="width:130px" placeholder="127.0.0.1"/></td>
      <td><input type="number" class="l-port" value="${l.port}" min="1" max="65535" style="width:90px"/></td>
      <td><button class="btn danger l-del">Remove</button></td>
    </tr>
  `).join("");

  $("#content").innerHTML = `
    <div class="card">
      <h2>Listeners</h2>
      <div class="desc">Each row is one listener. You can bind multiple IPs and ports simultaneously.
        Low ports (&lt;1024) require running as Administrator.
        Use different IPs (e.g. 127.0.0.1, 127.0.0.2) to listen on the same port via separate addresses.</div>
      <table>
        <thead><tr>
          <th>On</th><th>ID</th><th>Scheme</th><th>Bind IP</th><th>Port</th><th></th>
        </tr></thead>
        <tbody id="l-rows">${rows || '<tr><td colspan="6" class="muted">No listeners. Click + Add.</td></tr>'}</tbody>
      </table>
      <div class="row" style="margin-top:10px">
        <button class="btn secondary" id="l-add">+ Add listener</button>
        <button class="btn" id="btn-save">Save</button>
        <span class="muted">After saving, click "Start all enabled" in Server tab.</span>
      </div>
    </div>
    <div class="card">
      <h2>Other settings</h2>
      <div class="split">
        <label>Python interpreter (optional, default "python")
          <input id="s-python" type="text" value="${escapeAttr(c.python_path || "")}" placeholder="python"/></label>
        <label class="inline" style="align-self:end">
          <input id="s-auto" type="checkbox" ${c.auto_start_server ? "checked" : ""}/>
          Auto-start enabled listeners on app launch
        </label>
      </div>
    </div>
    <div class="card">
      <h2>Autostart with Windows</h2>
      <div class="desc">Register a per-user run entry so the app launches with Windows.</div>
      <div class="row">
        <button class="btn" id="btn-auto-en">Enable</button>
        <button class="btn secondary" id="btn-auto-dis">Disable</button>
      </div>
    </div>
  `;

  $("#l-add").onclick = () => {
    const newL = {
      id: "listener-" + (Date.now() % 100000),
      enabled: true,
      scheme: "http",
      bind: "127.0.0.1",
      port: 8080,
    };
    state.config = { ...state.config, listeners: [...(state.config.listeners || []), newL] };
    render();
  };

  $$("#l-rows tr").forEach((tr) => {
    const i = parseInt(tr.dataset.i, 10);
    const del = tr.querySelector(".l-del");
    if (del) del.onclick = () => {
      const list = [...state.config.listeners];
      list.splice(i, 1);
      state.config = { ...state.config, listeners: list };
      render();
    };
  });

  $("#btn-save").onclick = async () => {
    // Collect listener rows.
    const list = $$("#l-rows tr").filter((tr) => tr.dataset.i !== undefined).map((tr) => ({
      id: tr.querySelector(".l-id").value.trim(),
      enabled: tr.querySelector(".l-en").checked,
      scheme: tr.querySelector(".l-scheme").value,
      bind: tr.querySelector(".l-bind").value.trim() || "127.0.0.1",
      port: parseInt(tr.querySelector(".l-port").value, 10) || 8080,
    }));
    // Validate unique IDs.
    const ids = new Set();
    for (const l of list) {
      if (!l.id) { toast("Each listener needs an ID", true); return; }
      if (ids.has(l.id)) { toast("Duplicate listener ID: " + l.id, true); return; }
      ids.add(l.id);
    }
    // IMPORTANT: send the full config so unrelated fields (like `redirects`)
    // are not wiped by serde defaults on the backend.
    const newCfg = {
      ...state.config,
      listeners: list,
      auto_start_server: $("#s-auto").checked,
      python_path: $("#s-python").value || null,
      redirects: state.config?.redirects || [],
    };
    try {
      state.config = await invoke("save_config", { config: newCfg });
      toast("Saved");
      render();
    } catch (e) { toast("Save failed: " + e, true); }
  };

  $("#btn-auto-en").onclick = async () => {
    try { await autostartEnable(); toast("Autostart enabled"); } catch (e) { toast("" + e, true); }
  };
  $("#btn-auto-dis").onclick = async () => {
    try { await autostartDisable(); toast("Autostart disabled"); } catch (e) { toast("" + e, true); }
  };
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
function escapeAttr(s) {
  return escapeHtml(s).replaceAll('"', "&quot;");
}

// Bootstrap
render().catch((e) => console.error("render() failed:", e));
setInterval(refreshStatus, 2000);
