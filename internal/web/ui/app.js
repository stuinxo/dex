(function () {
  "use strict";

  var csrfToken = "";
  var currentState = null;
  var currentSecrets = {};
  var statusInfo = null;
  var probeResultsMap = {};
  var logSource = null;
  var lastLogSeq = 0;
  var logsPaused = false;
  var clientAutoProbed = false;

  var NODESM_META = {
    youtube: { label: "YouTube", cls: "brand-youtube" },
    netflix: { label: "NETFLIX", cls: "brand-netflix" },
    hdh: { label: "HBO / Disney+ / Hulu", cls: "brand-hdh" },
    tvb: { label: "TVB", cls: "brand-tvb" },
    bahamut: { label: "巴哈姆特", cls: "brand-bahamut" },
    openai: { label: "OpenAI", cls: "brand-openai" },
    claude: { label: "Claude", cls: "brand-claude" },
    gemini: { label: "Gemini", cls: "brand-gemini" },
    grok: { label: "Grok", cls: "brand-grok" },
    meta: { label: "Meta / Muse", cls: "brand-meta" },
    telegram: { label: "Telegram", cls: "brand-telegram" },
    twitter: { label: "X / Twitter", cls: "brand-twitter" },
    discord: { label: "Discord", cls: "brand-discord" },
    reddit: { label: "Reddit", cls: "brand-reddit" },
    github: { label: "GitHub", cls: "brand-github" },
    wikipedia: { label: "Wikipedia", cls: "brand-wikipedia" }
  };

  function $(id) { return document.getElementById(id); }

  function make(tag, cls, text) {
    var el = document.createElement(tag);
    if (cls) { el.className = cls; }
    if (text !== undefined && text !== null) { el.textContent = String(text); }
    return el;
  }

  function clearEl(el) {
    while (el.firstChild) { el.removeChild(el.firstChild); }
  }

  function showToast(msg, isErr) {
    var t = $("toast");
    t.textContent = msg;
    t.className = isErr ? "toast err" : "toast";
    setTimeout(function () { t.classList.add("hidden"); }, 3500);
  }

  async function api(method, path, body) {
    var opts = {
      method: method,
      credentials: "same-origin",
      headers: {}
    };
    if (csrfToken && method !== "GET") {
      opts.headers["X-CSRF-Token"] = csrfToken;
    }
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    var resp = await fetch(path, opts);
    var text = await resp.text();
    var data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { error: text }; }
    if (!resp.ok) {
      throw new Error(data.error || ("HTTP " + resp.status));
    }
    return data;
  }

  function splitList(raw) {
    return String(raw || "")
      .split(/[\n,]+/)
      .map(function (s) { return s.trim(); })
      .filter(Boolean);
  }

  function defaultListenAddrForRole(role) {
    if (role === "client") { return ":443"; }
    if (role === "server") { return "127.0.0.1:8443"; }
    return ":8443";
  }

  function formatArchShort(arch) {
    var s = String(arch || "").toUpperCase();
    if (s.indexOf("AMD64") >= 0) { return "AMD64"; }
    if (s.indexOf("ARM64") >= 0) { return "ARM64"; }
    return s || "LINUX";
  }

  function genUUID() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    var hex = "0123456789abcdef";
    var out = "";
    for (var i = 0; i < 36; i++) {
      if (i === 8 || i === 13 || i === 18 || i === 23) { out += "-"; continue; }
      var r = Math.floor(Math.random() * 16);
      if (i === 14) { r = 4; }
      if (i === 19) { r = (r & 3) | 8; }
      out += hex[r];
    }
    return out;
  }

  function formatDuration(sec) {
    sec = Math.max(0, Number(sec || 0));
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    if (d > 0) { return d + "d " + h + "h " + m + "m"; }
    return h + "h " + m + "m " + s + "s";
  }

  function openModal(title, builder) {
    $("modal-title").textContent = title;
    var body = $("modal-body");
    clearEl(body);
    builder(body);
    $("modal-backdrop").classList.remove("hidden");
  }

  function closeModal() {
    $("modal-backdrop").classList.add("hidden");
  }

  function showQRModal(title, uri) {
    openModal(title, function (body) {
      if (!uri) {
        body.appendChild(make("p", "text-muted", "暂无可用链接（请先保存并应用配置）。"));
        return;
      }
      var wrap = make("div", "qr-wrap");
      wrap.appendChild(window.DexQR.createSVG(uri, 220));
      body.appendChild(wrap);
      var ta = make("textarea", "form-control");
      ta.rows = 3;
      ta.readOnly = true;
      ta.value = uri;
      body.appendChild(ta);
    });
  }

  function setTab(tabName) {
    var titleText = "状态";
    var tabs = document.querySelectorAll("#main-tabs .tab");
    tabs.forEach(function (t) {
      var active = t.getAttribute("data-tab") === tabName;
      t.classList.toggle("active", active);
      if (active) {
        titleText = t.getAttribute("data-title") || t.textContent.trim();
      }
    });
    $("breadcrumb-current").textContent = tabName === "overview" ? "状态" : titleText;
    var panels = document.querySelectorAll(".tab-panel");
    panels.forEach(function (p) {
      p.classList.toggle("active", p.id === "tab-" + tabName);
    });
    if (tabName === "dns") {
      loadRulesStatus();
    }
    if (window.innerWidth < 768) {
      $("app-view").classList.remove("sidebar-toggled");
    }
  }

  function applyRoleVisibility(role) {
    var r = role || "client";
    var activeVisible = false;
    var activeTab = document.querySelector("#main-tabs .tab.active");
    var activeName = activeTab ? activeTab.getAttribute("data-tab") : "overview";

    document.querySelectorAll("#main-tabs .tab").forEach(function (t) {
      var rolesAttr = t.getAttribute("data-roles") || "all";
      var allowed = rolesAttr === "all" || rolesAttr.split(",").indexOf(r) >= 0;
      t.closest(".nav-item").classList.toggle("hidden", !allowed);
      if (allowed && t.getAttribute("data-tab") === activeName) {
        activeVisible = true;
      }
    });
    if (!activeVisible) {
      setTab("overview");
    }

    var isClient = r === "client";
    var isSrvOrLanding = r === "server" || r === "landing";
    $("overview-client-nodes").classList.toggle("hidden", !isClient);
    $("overview-server-share").classList.toggle("hidden", !isSrvOrLanding);

    var migKind = $("mig-kind");
    if (migKind && !isClient && migKind.value === "v2_client") {
      migKind.value = "v2_server";
    }
  }

  async function initSession() {
    try {
      var res = await api("GET", "/api/v1/auth/session");
      if (res.authenticated) {
        csrfToken = res.csrf_token || "";
        $("login-view").classList.add("hidden");
        $("app-view").classList.remove("hidden");
        await refreshAll();
        connectLogs();
        return;
      }
    } catch (_) {}
    $("app-view").classList.add("hidden");
    $("login-view").classList.remove("hidden");
  }

  async function refreshAll() {
    var stRes = await api("GET", "/api/v1/status");
    statusInfo = stRes;
    var stateRes = await api("GET", "/api/v1/state");
    currentState = stateRes.state;
    currentSecrets = stateRes.secrets || {};
    applyRoleVisibility(currentState.role);
    renderStatus();
    renderStateForms();
    if (currentState && currentState.role === "client" && !clientAutoProbed) {
      clientAutoProbed = true;
      runConnectivityProbe(true);
    }
  }

  function addKV(container, k, v) {
    var row = make("div", "kv-row");
    row.appendChild(make("span", "text-muted", k));
    var valEl = make("span", "mono", v);
    row.appendChild(valEl);
    container.appendChild(row);
  }

  function renderStatus() {
    if (!statusInfo) { return; }
    var alias = statusInfo.device_alias || statusInfo.hostname || "";
    document.title = alias ? (alias + " · 寒月 DEX v3") : "寒月 · DEX v3";

    var hostLabel = $("nav-host-label");
    if (alias) {
      hostLabel.textContent = alias;
      hostLabel.classList.remove("hidden");
    } else {
      hostLabel.textContent = "";
      hostLabel.classList.add("hidden");
    }

    $("role-badge").textContent = statusInfo.role || "client";
    $("arch-badge").textContent = formatArchShort(statusInfo.arch);
    $("kpi-version").textContent = "DEX " + (statusInfo.version || "v3");
    $("kpi-role-arch").textContent = (statusInfo.role || "client") + " · " + formatArchShort(statusInfo.arch).toLowerCase();
    $("kpi-uptime").textContent = formatDuration(statusInfo.uptime_sec);
    $("kpi-kernel").textContent = statusInfo.kernel ? ("Linux " + statusInfo.kernel.split("-")[0]) : "-";

    // Proxy toggle card state
    var paused = !!statusInfo.proxy_paused;
    var proxyStateTag = $("kpi-proxy-state");
    var btnStop = $("btn-proxy-stop");
    if (paused) {
      proxyStateTag.textContent = "已暂停";
      proxyStateTag.className = "kpi-state-tag paused";
      btnStop.textContent = "恢复代理";
      btnStop.className = "btn btn-warning btn-pill";
    } else {
      proxyStateTag.textContent = "运行中";
      proxyStateTag.className = "kpi-state-tag";
      btnStop.textContent = "关闭代理";
      btnStop.className = "btn btn-light btn-pill";
    }

    var svcGrid = $("svc-grid");
    clearEl(svcGrid);
    var svcs = statusInfo.services || {};
    Object.keys(svcs).sort().forEach(function (name) {
      var pill = make("div", "svc-pill");
      pill.appendChild(make("span", "", name));
      pill.appendChild(make("span", svcs[name] ? "dot on" : "dot"));
      svcGrid.appendChild(pill);
    });

    var sysKV = $("sys-kv");
    clearEl(sysKV);
    addKV(sysKV, "备注 / 主机名", (statusInfo.device_alias || "-") + " / " + (statusInfo.hostname || "-"));
    addKV(sysKV, "架构 / Init / 内核", (statusInfo.arch || "-") + " · " + (statusInfo.init_system || "-") + (statusInfo.kernel ? (" · " + statusInfo.kernel) : ""));
    addKV(sysKV, "内存 / 运行时长", (statusInfo.mem_mb || 0) + " MiB / " + formatDuration(statusInfo.uptime_sec));
    if (paused) {
      addKV(sysKV, "代理状态", "已暂停 (国内 MosDNS 保持运行)");
    }
    if (statusInfo.cert) {
      var c = statusInfo.cert;
      addKV(sysKV, "证书 CN / 到期", (c.common_name || "-") + " (" + String(c.not_after || "").slice(0, 10) + ")");
      addKV(sysKV, "证书状态", c.self_signed ? "自签" : (c.chain_valid ? "CA 有效" : "待验证"));
    }

    if (currentState && currentState.role === "client") {
      renderOverviewNodes();
    } else if (currentState && (currentState.role === "server" || currentState.role === "landing")) {
      var shareKV = $("server-share-kv");
      clearEl(shareKV);
      addKV(shareKV, "主入站协议", (currentState.server.protocol || "vless-xhttp") + " (" + (currentState.server.tls_mode || "nginx") + ")");
      addKV(shareKV, "主节点 URI", statusInfo.server_main_uri || "-");
      var btnDoh = $("btn-server-doh-qr");
      if (statusInfo.doh_url) {
        addKV(shareKV, "DoH 端点", statusInfo.doh_url);
        btnDoh.classList.remove("hidden");
      } else {
        btnDoh.classList.add("hidden");
      }
    }

    renderCertSummary();
  }

  function renderOverviewNodes() {
    var tbody = $("overview-nodes-tbody");
    clearEl(tbody);
    var nodes = (currentState && currentState.client && currentState.client.nodes) || [];
    var activeID = currentState && currentState.client && currentState.client.active_node_id;
    if (nodes.length === 0) {
      var emptyTr = make("tr");
      var emptyTd = make("td", "text-muted text-center", "暂无节点，请前往「节点管理」添加。");
      emptyTd.colSpan = 6;
      emptyTr.appendChild(emptyTd);
      tbody.appendChild(emptyTr);
      return;
    }

    nodes.forEach(function (n, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "", String(idx + 1)));
      tr.appendChild(make("td", "mono", n.address + ":" + n.port));
      tr.appendChild(make("td", "text-left", n.name || n.id));
      tr.appendChild(make("td", "", n.protocol || ""));

      var tdLat = make("td");
      var pr = probeResultsMap[n.id];
      if (!pr) {
        tdLat.appendChild(make("span", "text-muted", "-"));
      } else if (pr.healthy) {
        tdLat.appendChild(make("span", "text-success", pr.latency_ms + " ms"));
      } else {
        tdLat.appendChild(make("span", "text-danger", pr.error || "不可达"));
      }
      tr.appendChild(tdLat);

      var tdAct = make("td");
      var isActive = n.id === activeID;
      var bSwitch = make("button", isActive ? "btn btn-success btn-sm" : "btn btn-outline-secondary btn-sm", isActive ? "当前" : "切换");
      bSwitch.type = "button";
      bSwitch.addEventListener("click", async function () {
        try {
          await api("POST", "/api/v1/nodes/select", { node_id: n.id });
          showToast("已切换至 " + (n.name || n.id));
          await refreshAll();
        } catch (e) { showToast(e.message, true); }
      });
      tdAct.appendChild(bSwitch);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
  }

  function renderNodeSelectOptions(sel, nodes, selectedID, includeEmptyLabel) {
    clearEl(sel);
    if (includeEmptyLabel !== null) {
      var empty = make("option", "", includeEmptyLabel);
      empty.value = "";
      sel.appendChild(empty);
    }
    nodes.forEach(function (n) {
      var opt = make("option", "", (n.name || n.id) + " (" + n.protocol + ")");
      opt.value = n.id;
      if (n.id === selectedID) { opt.selected = true; }
      sel.appendChild(opt);
    });
  }

  function refreshClientNodeSelects(deletedNodeID) {
    var nodes = (currentState && currentState.client && currentState.client.nodes) || [];
    var targets = [
      { el: $("divert-node"), emptyLabel: "(同主节点)" },
      { el: $("apple-node"), emptyLabel: "(中国直连)" },
      { el: $("custom-node"), emptyLabel: "(同主节点)" },
      { el: $("fwd1-upstream"), emptyLabel: "(跟随默认)" }
    ];
    targets.forEach(function (t) {
      if (!t.el) { return; }
      var curVal = t.el.value === deletedNodeID ? "" : t.el.value;
      renderNodeSelectOptions(t.el, nodes, curVal, t.emptyLabel);
    });
    document.querySelectorAll("[data-nodesm-svc]").forEach(function (sel) {
      var curVal = sel.value === deletedNodeID ? "" : sel.value;
      renderNodeSelectOptions(sel, nodes, curVal, "(跟随默认)");
    });
  }

  function renderStateForms() {
    if (!currentState) { return; }
    var role = currentState.role;
    if (role === "client") {
      renderClientForms();
    } else {
      renderServerRelayForms();
    }
    renderSharedSystemForms();
  }

  function renderClientForms() {
    var c = currentState.client;
    var nodes = c.nodes || [];
    $("failover-enabled").checked = !!c.failover_enabled;
    renderNodesTable();

    // NodeDT
    var div = c.routing.divert || {};
    $("divert-enabled").checked = !!div.enabled;
    renderNodeSelectOptions($("divert-node"), nodes, div.node_id || "", "(同主节点)");
    $("divert-chn-lan").value = (div.chn_proxy_lan_ips || []).join("\n");
    $("divert-global-lan").value = (div.global_proxy_lan_ips || []).join("\n");
    $("divert-direct-lan").value = (div.direct_lan_ips || []).join("\n");

    // NodeSM with classic brand tags
    var smGrid = $("nodesm-grid");
    clearEl(smGrid);
    var services = (statusInfo && statusInfo.node_sm_services) || [];
    var smMap = c.routing.service_map || {};
    services.forEach(function (svc) {
      var meta = NODESM_META[svc] || { label: svc, cls: "" };
      var grp = make("div", "nodesm-group");
      var tag = make("span", "nodesm-tag" + (meta.cls ? (" " + meta.cls) : ""), meta.label);
      var sel = make("select", "form-control");
      sel.setAttribute("data-nodesm-svc", svc);
      renderNodeSelectOptions(sel, nodes, smMap[svc] || "", "(跟随默认)");
      grp.appendChild(tag);
      grp.appendChild(sel);
      smGrid.appendChild(grp);
    });
    renderNodeSelectOptions($("apple-node"), nodes, c.routing.apple_node_id || "", "(中国直连)");
    $("steam-proxy").checked = !!c.routing.steam_proxy;

    // NodeCU
    var cu = c.routing.custom || {};
    $("custom-enabled").checked = !!cu.enabled;
    renderNodeSelectOptions($("custom-node"), nodes, cu.node_id || "", "(同主节点)");
    $("custom-domains").value = (cu.domains || []).join("\n");
    $("custom-ips").value = (cu.ips || []).join("\n");

    // DNS
    var dns = c.dns || {};
    $("dns-block-ads").checked = !!dns.block_ads;
    $("dns-block53").checked = !!dns.block_external_53;
    $("dns-ipv6").checked = !!(currentState.system && currentState.system.enable_ipv6);
    $("dns-auto-rules").checked = !!(currentState.system && currentState.system.auto_update_rules);
    $("dns-china").value = (dns.china_servers || []).join("\n");
    $("dns-doh").value = (dns.doh_servers || []).join("\n");
    var hostsLines = [];
    Object.keys(dns.hosts || {}).sort().forEach(function (k) {
      hostsLines.push(k + " = " + dns.hosts[k]);
    });
    $("dns-hosts").value = hostsLines.join("\n");
    $("dns-white-dom").value = (dns.whitelist_domains || []).join("\n");
    $("dns-black-dom").value = (dns.blacklist_domains || []).join("\n");
    $("dns-white-ip").value = (dns.whitelist_ips || []).join("\n");
    $("dns-black-ip").value = (dns.blacklist_ips || []).join("\n");

    // FWD0 / FWD1
    var f0 = c.fwd0 || {};
    $("fwd0-enabled").checked = !!f0.enabled;
    $("fwd0-proto").value = f0.protocol || "vless-xhttp";
    $("fwd0-port").value = f0.port || 9800;
    $("fwd0-path").value = f0.path || "";
    $("fwd0-uuids").value = (f0.uuids || []).join("\n");

    var f1 = c.fwd1 || {};
    $("fwd1-enabled").checked = !!f1.enabled;
    $("fwd1-proto").value = f1.protocol || "vless-xhttp";
    $("fwd1-port").value = f1.port || 9801;
    renderNodeSelectOptions($("fwd1-upstream"), nodes, f1.upstream_node_id || "", "(跟随默认)");
    $("fwd1-path").value = f1.path || "";
    $("fwd1-uuids").value = (f1.uuids || []).join("\n");

    renderRelayTable($("client-relay-tbody"));

    // RproxyC
    var rc = c.rproxyc || {};
    $("rc-enabled").checked = !!rc.enabled;
    $("rc-domain").value = rc.tunnel_address || "";
    $("rc-port").value = rc.tunnel_port || 20000;
    $("rc-uuid").value = rc.tunnel_uuid || "";
    $("rc-security").value = rc.security || "tls";
    $("rc-sni").value = rc.server_name || "";
    $("rc-pin").value = rc.pinned_peer_cert_sha256 || "";
    $("rc-out-direct").checked = !!rc.out_direct;
    renderRproxyCMappings();

    // WG
    var wg = c.wireguard || {};
    $("wg-enabled").checked = !!wg.enabled;
    $("wg-endpoint").value = wg.endpoint_host || "";
    $("wg-port").value = wg.listen_port || 51820;
    $("wg-subnet").value = wg.subnet_cidr || "172.16.66.1/24";
    $("wg-server-pub").value = wg.server_public_key || "";
    renderWGPeers();

    // DDNS
    var ddns = c.ddns || {};
    $("ddns-enabled").checked = !!ddns.enabled;
    $("ddns-domain").value = ddns.domain || "";
    $("ddns-email").value = ddns.cf_email || "";
    $("ddns-token").value = "";
    $("ddns-token").placeholder = currentSecrets.has_ddns_cf_token ? "已保存 Token (留空不变)" : "输入 CF API Token";
    $("ddns-v6").checked = !!ddns.enable_ipv6;
  }

  function renderServerRelayForms() {
    var role = currentState.role;
    if (role === "server" || role === "landing") {
      var srv = currentState.server || {};
      $("srv-proto").value = srv.protocol || "vless-xhttp";
      $("srv-tls-mode").value = srv.tls_mode || "nginx";
      $("srv-domain").value = srv.domain || "";
      $("srv-connect-host").value = srv.connect_host || "";
      $("srv-port").value = srv.listen_port || 443;
      $("srv-pub-port").value = srv.public_port || 0;
      $("srv-path").value = srv.path || "";
      $("srv-camo-dir").value = srv.camouflage_dir || "";
      $("srv-uuids").value = (srv.uuids || []).join("\n");
      $("srv-enable-doh").checked = !!srv.enable_doh;
      renderSocks5Table();
    }
    renderExtraTable();
    renderRelayTable($("srv-relay-tbody"));

    var rs = currentState.rproxys || {};
    $("rs-enabled").checked = !!rs.enabled;
    $("rs-domain").value = rs.domain || "";
    $("rs-port").value = rs.listen_port || 20000;
    $("rs-security").value = rs.security || "tls";
    $("rs-uuids").value = (rs.uuids || []).join("\n");
    $("rs-in-uuids").value = (rs.in_uuids || []).join("\n");
    renderRproxySMappings();
  }

  function renderSharedSystemForms() {
    var cert = currentState.cert || {};
    $("cert-domain").value = cert.domain || (currentState.server && currentState.server.domain) || "";
    $("cert-cf-email").value = cert.cf_email || "";
    $("cert-cf-token").value = "";
    $("cert-cf-token").placeholder = currentSecrets.has_cert_cf_token ? "已保存 Token (留空沿用)" : "输入 CF Token";
    $("cert-auto-renew").checked = cert.auto_renew !== false;

    var defListen = defaultListenAddrForRole(currentState.role);
    $("sys-hostname").value = (currentState.system && currentState.system.hostname) || "";
    $("sys-auto-update-core").checked = !!(currentState.system && currentState.system.auto_update_core);
    $("auth-listen").placeholder = defListen;
    $("auth-listen").value = (currentState.auth && currentState.auth.listen_addr) || defListen;
  }

  function renderCertSummary() {
    var box = $("cert-summary");
    if (!box) { return; }
    clearEl(box);
    var c = statusInfo && statusInfo.cert;
    if (!c) {
      addKV(box, "状态", "尚未检测到有效证书文件");
      return;
    }
    addKV(box, "CN / SANs", (c.common_name || "-") + " | " + (c.sans || []).join(", "));
    addKV(box, "有效期至", String(c.not_after || "").slice(0, 19).replace("T", " "));
    addKV(box, "类型", c.self_signed ? "自签证书" : (c.chain_valid ? "受信任 CA 证书" : "证书链异常"));
  }

  function renderNodesTable() {
    var tbody = $("nodes-tbody");
    clearEl(tbody);
    var nodes = (currentState && currentState.client && currentState.client.nodes) || [];
    var activeID = currentState && currentState.client && currentState.client.active_node_id;

    nodes.forEach(function (n, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "", n.id === activeID ? "★ 活动" : ""));
      tr.appendChild(make("td", "", n.name || n.id));
      tr.appendChild(make("td", "", n.protocol || ""));
      tr.appendChild(make("td", "mono", n.address + ":" + n.port));
      tr.appendChild(make("td", "mono", n.tls_sni || n.address));

      var tdLat = make("td");
      var pr = probeResultsMap[n.id];
      if (!pr) {
        tdLat.appendChild(make("span", "text-muted", "-"));
      } else if (pr.healthy) {
        tdLat.appendChild(make("span", "status-badge ok", pr.latency_ms + " ms"));
      } else {
        tdLat.appendChild(make("span", "status-badge fail", pr.error || "失败"));
      }
      tr.appendChild(tdLat);

      var tdAct = make("td");
      var actWrap = make("div", "row-gap");
      var bSel = make("button", n.id === activeID ? "btn btn-success btn-sm" : "btn btn-outline-secondary btn-sm", "切换");
      bSel.type = "button";
      bSel.addEventListener("click", async function () {
        try {
          await api("POST", "/api/v1/nodes/select", { node_id: n.id });
          showToast("已切换主节点");
          await refreshAll();
        } catch (e) { showToast(e.message, true); }
      });
      var bUp = make("button", "btn btn-sm", "↑");
      bUp.type = "button";
      bUp.disabled = idx === 0;
      bUp.addEventListener("click", function () {
        if (idx > 0) {
          var arr = currentState.client.nodes;
          var tmp = arr[idx - 1]; arr[idx - 1] = arr[idx]; arr[idx] = tmp;
          renderNodesTable();
        }
      });
      var bDown = make("button", "btn btn-sm", "↓");
      bDown.type = "button";
      bDown.disabled = idx === nodes.length - 1;
      bDown.addEventListener("click", function () {
        if (idx < nodes.length - 1) {
          var arr = currentState.client.nodes;
          var tmp = arr[idx + 1]; arr[idx + 1] = arr[idx]; arr[idx] = tmp;
          renderNodesTable();
        }
      });
      var bEdit = make("button", "btn btn-sm", "编辑");
      bEdit.type = "button";
      bEdit.addEventListener("click", function () { openNodeModal(n, idx); });
      var bQR = make("button", "btn btn-sm", "QR");
      bQR.type = "button";
      bQR.addEventListener("click", function () {
        var uri = (statusInfo && statusInfo.node_uris && statusInfo.node_uris[n.id]) || "";
        showQRModal(n.name || n.id, uri);
      });
      var bDel = make("button", "btn btn-sm btn-outline-danger", "删");
      bDel.type = "button";
      bDel.addEventListener("click", function () {
        currentState.client.nodes.splice(idx, 1);
        if (currentState.client.active_node_id === n.id) {
          currentState.client.active_node_id = currentState.client.nodes[0] ? currentState.client.nodes[0].id : "";
        }
        var c = currentState.client;
        if (c.routing) {
          if (c.routing.service_map) {
            Object.keys(c.routing.service_map).forEach(function (svc) {
              if (c.routing.service_map[svc] === n.id) {
                delete c.routing.service_map[svc];
              }
            });
          }
          if (c.routing.apple_node_id === n.id) { c.routing.apple_node_id = ""; }
          if (c.routing.divert && c.routing.divert.node_id === n.id) { c.routing.divert.node_id = ""; }
          if (c.routing.custom && c.routing.custom.node_id === n.id) { c.routing.custom.node_id = ""; }
        }
        if (c.fwd1 && c.fwd1.upstream_node_id === n.id) { c.fwd1.upstream_node_id = ""; }
        renderNodesTable();
        renderOverviewNodes();
        refreshClientNodeSelects(n.id);
      });

      actWrap.appendChild(bSel);
      actWrap.appendChild(bUp);
      actWrap.appendChild(bDown);
      actWrap.appendChild(bEdit);
      actWrap.appendChild(bQR);
      actWrap.appendChild(bDel);
      tdAct.appendChild(actWrap);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
  }

  function openNodeModal(existing, idx) {
    var isNew = !existing;
    var node = existing ? JSON.parse(JSON.stringify(existing)) : {
      id: "node-" + Date.now().toString().slice(-6),
      name: "",
      protocol: "vless-xhttp",
      address: "",
      port: 443,
      uuid: genUUID(),
      tls_sni: "",
      path: "",
      reality_pubkey: "",
      reality_shortid: "",
      username: "",
      password: ""
    };

    openModal(isNew ? "添加节点" : "编辑节点: " + (node.name || node.id), function (body) {
      if (isNew) {
        var uriRow = make("div", "mb");
        var uriInp = make("input", "form-control");
        uriInp.type = "text";
        uriInp.placeholder = "粘贴 vless:// / vmess:// / socks5:// 链接自动解析...";
        var btnParse = make("button", "btn btn-sm btn-outline-primary mt", "解析链接填充");
        btnParse.type = "button";
        uriRow.appendChild(make("label", "field-label-inline", "从分享链接快速导入"));
        uriRow.appendChild(uriInp);
        uriRow.appendChild(btnParse);
        body.appendChild(uriRow);

        btnParse.addEventListener("click", async function () {
          try {
            var res = await api("POST", "/api/v1/nodes/parse-uri", { uri: uriInp.value });
            var parsed = res.node || {};
            if (parsed.protocol) { fProto.value = parsed.protocol; }
            if (parsed.name) { fName.value = parsed.name; }
            if (parsed.address) { fAddr.value = parsed.address; }
            if (parsed.port) { fPort.value = parsed.port; }
            if (parsed.uuid) { fUUID.value = parsed.uuid; }
            if (parsed.tls_sni) { fSNI.value = parsed.tls_sni; }
            if (parsed.path) { fPath.value = parsed.path; }
            if (parsed.reality_pubkey) { fPBK.value = parsed.reality_pubkey; }
            if (parsed.reality_shortid) { fSID.value = parsed.reality_shortid; }
            if (parsed.username) { fUser.value = parsed.username; }
            if (parsed.password) { fPass.value = parsed.password; }
            updateProtoFields();
            showToast("解析成功");
          } catch (e) { showToast(e.message, true); }
        });
      }

      function addField(labelText, inputEl) {
        var lbl = make("label", "field mt");
        lbl.appendChild(make("span", "", labelText));
        inputEl.classList.add("form-control");
        lbl.appendChild(inputEl);
        body.appendChild(lbl);
        return inputEl;
      }

      var fName = addField("名称", make("input")); fName.value = node.name || "";
      var fProto = make("select");
      ["vless-xhttp", "vless-reality", "vless-ws", "vmess-ws", "vmess-tcp", "socks5"].forEach(function (p) {
        var o = make("option", "", p); o.value = p;
        if (p === node.protocol) { o.selected = true; }
        fProto.appendChild(o);
      });
      addField("协议", fProto);

      var fAddr = addField("服务器地址", make("input")); fAddr.value = node.address || "";
      var fPort = addField("端口", make("input")); fPort.type = "number"; fPort.value = node.port || 443;
      var fUUID = addField("UUID", make("input")); fUUID.value = node.uuid || "";
      var fSNI = addField("TLS SNI (留空同地址)", make("input")); fSNI.value = node.tls_sni || "";
      var fPath = addField("Path (XHTTP / WS)", make("input")); fPath.value = node.path || "";
      var fPBK = addField("Reality PublicKey", make("input")); fPBK.value = node.reality_pubkey || "";
      var fSID = addField("Reality ShortID", make("input")); fSID.value = node.reality_shortid || "";
      var fUser = addField("SOCKS5 用户名", make("input")); fUser.value = node.username || "";
      var fPass = addField("SOCKS5 密码", make("input")); fPass.type = "password"; fPass.value = node.password || "";

      function updateProtoFields() {
        var p = fProto.value;
        fUUID.parentElement.classList.toggle("hidden", p === "socks5");
        fSNI.parentElement.classList.toggle("hidden", p === "vmess-tcp" || p === "socks5");
        fPath.parentElement.classList.toggle("hidden", p !== "vless-xhttp" && p !== "vless-ws" && p !== "vmess-ws");
        fPBK.parentElement.classList.toggle("hidden", p !== "vless-reality");
        fSID.parentElement.classList.toggle("hidden", p !== "vless-reality");
        fUser.parentElement.classList.toggle("hidden", p !== "socks5");
        fPass.parentElement.classList.toggle("hidden", p !== "socks5");
      }
      fProto.addEventListener("change", updateProtoFields);
      updateProtoFields();

      var btnOK = make("button", "btn btn-primary mt", isNew ? "添加到列表" : "确认修改");
      btnOK.type = "button";
      btnOK.addEventListener("click", function () {
        var next = {
          id: node.id,
          name: fName.value.trim() || fAddr.value.trim(),
          protocol: fProto.value,
          address: fAddr.value.trim(),
          port: Number(fPort.value || 443),
          uuid: fUUID.value.trim(),
          tls_sni: fSNI.value.trim(),
          path: fPath.value.trim(),
          reality_pubkey: fPBK.value.trim(),
          reality_shortid: fSID.value.trim(),
          username: fUser.value,
          password: fPass.value
        };
        if (!next.address) { showToast("地址不能为空", true); return; }
        if (isNew) {
          currentState.client.nodes.push(next);
          if (!currentState.client.active_node_id) {
            currentState.client.active_node_id = next.id;
          }
        } else {
          currentState.client.nodes[idx] = next;
        }
        renderNodesTable();
        renderOverviewNodes();
        closeModal();
      });
      body.appendChild(btnOK);
    });
  }

  function renderRelayTable(tbody) {
    clearEl(tbody);
    var rules = (currentState && currentState.relay && currentState.relay.forwards) || [];
    rules.forEach(function (rf, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "mono", rf.id));
      tr.appendChild(make("td", "", String(rf.listen_port)));
      tr.appendChild(make("td", "", String(rf.public_port || rf.listen_port)));
      tr.appendChild(make("td", "mono", rf.target_host + ":" + rf.target_port));
      tr.appendChild(make("td", "", rf.proto || "tcp"));
      tr.appendChild(make("td", "", rf.engine || "nft"));
      var td = make("td");
      var bDel = make("button", "btn btn-sm btn-outline-danger", "删");
      bDel.type = "button";
      bDel.addEventListener("click", function () {
        currentState.relay.forwards.splice(idx, 1);
        renderRelayTable(tbody);
      });
      td.appendChild(bDel);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }

  function openRelayModal(tbody) {
    openModal("添加端口转发规则", function (body) {
      function fld(lbl, el) {
        var l = make("label", "field mt");
        l.appendChild(make("span", "", lbl));
        el.classList.add("form-control");
        l.appendChild(el);
        body.appendChild(l);
        return el;
      }
      var fLP = fld("本机监听端口", make("input")); fLP.type = "number"; fLP.value = "10001";
      var fPP = fld("公网端口 (0 同监听端口)", make("input")); fPP.type = "number"; fPP.value = "0";
      var fTH = fld("目标主机/域名", make("input"));
      var fTP = fld("目标端口", make("input")); fTP.type = "number"; fTP.value = "443";
      var fProto = make("select");
      ["tcp", "udp", "tcp,udp"].forEach(function (p) { var o = make("option", "", p); o.value = p; fProto.appendChild(o); });
      fld("协议", fProto);
      var fEng = make("select");
      ["nft", "haproxy", "xray"].forEach(function (e) { var o = make("option", "", e); o.value = e; fEng.appendChild(o); });
      fld("引擎", fEng);

      var b = make("button", "btn btn-primary mt", "加入列表");
      b.type = "button";
      b.addEventListener("click", function () {
        var lp = Number(fLP.value);
        if (!lp || !fTH.value.trim() || !Number(fTP.value)) {
          showToast("请填写完整端口和目标地址", true);
          return;
        }
        currentState.relay.forwards = currentState.relay.forwards || [];
        var existingIDs = {};
        currentState.relay.forwards.forEach(function (f) { if (f.id) { existingIDs[f.id] = true; } });
        var fwdID = "fwd-" + lp;
        if (existingIDs[fwdID]) {
          var pTag = (fProto.value || "tcp").replace(/,/g, "-");
          fwdID = "fwd-" + pTag + "-" + lp;
          var suffix = 2;
          while (existingIDs[fwdID]) {
            fwdID = "fwd-" + pTag + "-" + lp + "-" + suffix;
            suffix++;
          }
        }
        currentState.relay.forwards.push({
          id: fwdID,
          listen_port: lp,
          public_port: Number(fPP.value || 0),
          target_host: fTH.value.trim(),
          target_port: Number(fTP.value),
          proto: fProto.value,
          engine: fEng.value
        });
        renderRelayTable(tbody);
        closeModal();
      });
      body.appendChild(b);
    });
  }

  function renderRproxyCMappings() {
    var tbody = $("rc-map-tbody");
    clearEl(tbody);
    var maps = (currentState && currentState.client && currentState.client.rproxyc && currentState.client.rproxyc.mappings) || [];
    maps.forEach(function (m, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "", String(m.ext_port)));
      tr.appendChild(make("td", "mono", m.int_ip));
      tr.appendChild(make("td", "", String(m.int_port)));
      tr.appendChild(make("td", "", m.proto || "tcp"));
      var td = make("td");
      var bDel = make("button", "btn btn-sm btn-outline-danger", "删");
      bDel.type = "button";
      bDel.addEventListener("click", function () {
        currentState.client.rproxyc.mappings.splice(idx, 1);
        renderRproxyCMappings();
      });
      td.appendChild(bDel);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }

  function renderRproxySMappings() {
    var tbody = $("rs-map-tbody");
    clearEl(tbody);
    var maps = (currentState && currentState.rproxys && currentState.rproxys.mappings) || [];
    maps.forEach(function (m, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "", String(m.port)));
      tr.appendChild(make("td", "", m.proto || "tcp"));
      var td = make("td");
      var bDel = make("button", "btn btn-sm btn-outline-danger", "删");
      bDel.type = "button";
      bDel.addEventListener("click", function () {
        currentState.rproxys.mappings.splice(idx, 1);
        renderRproxySMappings();
      });
      td.appendChild(bDel);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }

  function renderWGPeers() {
    var tbody = $("wg-peers-tbody");
    clearEl(tbody);
    var peers = (currentState && currentState.client && currentState.client.wireguard && currentState.client.wireguard.peers) || [];
    peers.forEach(function (p, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "", p.name));
      tr.appendChild(make("td", "mono", p.ip));
      tr.appendChild(make("td", "mono", (p.public_key || "").slice(0, 18) + "..."));
      var td = make("td");
      var wrap = make("div", "row-gap");

      var bCfg = make("button", "btn btn-sm", "配置 / QR");
      bCfg.type = "button";
      bCfg.addEventListener("click", async function () {
        try {
          var resp = await fetch("/api/v1/wireguard/peers/" + encodeURIComponent(p.name) + "/config", {
            credentials: "same-origin"
          });
          if (!resp.ok) {
            var errText = await resp.text();
            var errMsg = "获取配置失败 (" + resp.status + ")";
            try {
              var errObj = JSON.parse(errText);
              if (errObj && errObj.error) { errMsg = errObj.error; }
            } catch (_) {}
            showToast(errMsg, true);
            return;
          }
          var cfg = await resp.text();
          openModal("WireGuard Peer: " + p.name, function (body) {
            var qrBox = make("div", "qr-wrap");
            qrBox.appendChild(window.DexQR.createSVG(cfg, 220));
            body.appendChild(qrBox);
            var ta = make("textarea", "form-control");
            ta.rows = 10; ta.readOnly = true; ta.value = cfg;
            body.appendChild(ta);
          });
        } catch (e) { showToast(e.message, true); }
      });

      var bDl = make("a", "btn btn-sm", "下载 .conf");
      bDl.href = "/api/v1/wireguard/peers/" + encodeURIComponent(p.name) + "/config?download=1";
      bDl.download = "wg-" + p.name + ".conf";

      var bRegen = make("button", "btn btn-sm", "轮换密钥");
      bRegen.type = "button";
      bRegen.addEventListener("click", async function () {
        try {
          await api("POST", "/api/v1/wireguard/peers/" + encodeURIComponent(p.name) + "/regen", {});
          showToast("已重新生成 Peer 密钥: " + p.name);
          await refreshAll();
        } catch (e) { showToast(e.message, true); }
      });

      var bDel = make("button", "btn btn-sm btn-outline-danger", "删");
      bDel.type = "button";
      bDel.addEventListener("click", function () {
        currentState.client.wireguard.peers.splice(idx, 1);
        renderWGPeers();
      });

      wrap.appendChild(bCfg);
      wrap.appendChild(bDl);
      wrap.appendChild(bRegen);
      wrap.appendChild(bDel);
      td.appendChild(wrap);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }

  function renderSocks5Table() {
    var tbody = $("socks5-tbody");
    clearEl(tbody);
    var list = (currentState && currentState.server && currentState.server.socks5_outbounds) || [];
    list.forEach(function (prof, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "", prof.name));
      tr.appendChild(make("td", "", prof.enabled ? "启用" : "停用"));
      tr.appendChild(make("td", "mono", prof.address + ":" + prof.port));
      tr.appendChild(make("td", "", String((prof.domains || []).length)));
      tr.appendChild(make("td", "", String((prof.ips || []).length)));
      tr.appendChild(make("td", "", prof.private_bypass ? "是" : "否"));
      var td = make("td");
      var wrap = make("div", "row-gap");

      var bTest = make("button", "btn btn-sm", "测速");
      bTest.type = "button";
      bTest.addEventListener("click", async function () {
        try {
          var res = await api("POST", "/api/v1/socks5/test", {
            address: prof.address, port: prof.port, username: prof.username || "", password: prof.password || ""
          });
          var r = res.result || {};
          showToast(prof.name + ": 出口 " + (r.exit_ip || "?") + " (" + (r.location || "-") + ") " + (r.latency_ms || 0) + "ms");
        } catch (e) { showToast(e.message, true); }
      });

      var bToggle = make("button", "btn btn-sm", prof.enabled ? "停用" : "启用");
      bToggle.type = "button";
      bToggle.addEventListener("click", function () {
        prof.enabled = !prof.enabled;
        renderSocks5Table();
      });

      var bEdit = make("button", "btn btn-sm", "编辑");
      bEdit.type = "button";
      bEdit.addEventListener("click", function () { openSocks5Modal(prof, idx); });

      var bDel = make("button", "btn btn-sm btn-outline-danger", "删");
      bDel.type = "button";
      bDel.addEventListener("click", function () {
        currentState.server.socks5_outbounds.splice(idx, 1);
        renderSocks5Table();
      });

      wrap.appendChild(bTest);
      wrap.appendChild(bToggle);
      wrap.appendChild(bEdit);
      wrap.appendChild(bDel);
      td.appendChild(wrap);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }

  function openSocks5Modal(existing, idx) {
    var isNew = !existing;
    var prof = existing ? JSON.parse(JSON.stringify(existing)) : {
      name: "exit-" + (((currentState.server.socks5_outbounds || []).length) + 1),
      enabled: true,
      address: "",
      port: 1080,
      username: "",
      password: "",
      domains: [],
      ips: [],
      private_bypass: true
    };

    openModal(isNew ? "添加 SOCKS5 出口" : "编辑 SOCKS5: " + prof.name, function (body) {
      function fld(lbl, el) {
        var l = make("label", "field mt");
        l.appendChild(make("span", "", lbl));
        el.classList.add("form-control");
        l.appendChild(el);
        body.appendChild(l);
        return el;
      }
      var fName = fld("配置名称", make("input")); fName.value = prof.name;
      var fAddr = fld("SOCKS5 主机/IP", make("input")); fAddr.value = prof.address;
      var fPort = fld("端口", make("input")); fPort.type = "number"; fPort.value = prof.port || 1080;
      var fUser = fld("用户名 (可选)", make("input")); fUser.value = prof.username || "";
      var fPass = fld("密码 (可选)", make("input")); fPass.type = "password"; fPass.value = prof.password || "";
      var fDom = fld("域名规则 (每行或逗号，如 geosite:openai)", make("textarea")); fDom.rows = 3; fDom.value = (prof.domains || []).join("\n");
      var fIP = fld("IP/CIDR 规则 (每行或逗号，留空为全局兜底)", make("textarea")); fIP.rows = 2; fIP.value = (prof.ips || []).join("\n");
      var fPB = make("input"); fPB.type = "checkbox"; fPB.checked = prof.private_bypass !== false;
      var pbLbl = make("label", "check-row mt"); pbLbl.appendChild(fPB); pbLbl.appendChild(document.createTextNode(" 私有地址直连旁路 (private_bypass)"));
      body.appendChild(pbLbl);

      var b = make("button", "btn btn-primary mt", "确认");
      b.type = "button";
      b.addEventListener("click", function () {
        var next = {
          name: fName.value.trim(),
          enabled: prof.enabled !== false,
          address: fAddr.value.trim(),
          port: Number(fPort.value || 1080),
          username: fUser.value,
          password: fPass.value,
          domains: splitList(fDom.value),
          ips: splitList(fIP.value),
          private_bypass: fPB.checked
        };
        if (!next.name || !next.address) { showToast("名称和地址必填", true); return; }
        currentState.server.socks5_outbounds = currentState.server.socks5_outbounds || [];
        if (isNew) { currentState.server.socks5_outbounds.push(next); }
        else { currentState.server.socks5_outbounds[idx] = next; }
        renderSocks5Table();
        closeModal();
      });
      body.appendChild(b);
    });
  }

  function renderExtraTable() {
    var tbody = $("extra-tbody");
    clearEl(tbody);
    var list = (currentState && currentState.extra_inbounds) || [];
    list.forEach(function (ex, idx) {
      var tr = make("tr");
      tr.appendChild(make("td", "mono", ex.tag));
      tr.appendChild(make("td", "", ex.protocol));
      tr.appendChild(make("td", "", String(ex.listen_port)));
      tr.appendChild(make("td", "", ex.via_nginx ? "是" : "否"));
      var summary = "";
      if (ex.protocol === "vless-reality") { summary = "SNI=" + (ex.reality_sni || "-"); }
      else if (ex.protocol === "dokodemo") { summary = (ex.target_addr || "") + ":" + (ex.target_port || 0) + " (" + (ex.network || "tcp,udp") + ")"; }
      else if (ex.protocol === "socks5") { summary = ex.socks_user ? ("auth:" + ex.socks_user) : "no-auth"; }
      else { summary = (ex.domain || "(default)") + " " + (ex.path || "(auto)"); }
      tr.appendChild(make("td", "mono", summary));

      var td = make("td");
      var wrap = make("div", "row-gap");
      var uri = statusInfo && statusInfo.extra_uris && statusInfo.extra_uris[ex.tag];
      if (uri) {
        var bQR = make("button", "btn btn-sm", "QR");
        bQR.type = "button";
        bQR.addEventListener("click", function () { showQRModal(ex.tag, uri); });
        wrap.appendChild(bQR);
      }
      var bEdit = make("button", "btn btn-sm", "编辑");
      bEdit.type = "button";
      bEdit.addEventListener("click", function () { openExtraModal(ex, idx); });
      var bDel = make("button", "btn btn-sm btn-outline-danger", "删");
      bDel.type = "button";
      bDel.addEventListener("click", function () {
        currentState.extra_inbounds.splice(idx, 1);
        renderExtraTable();
      });
      wrap.appendChild(bEdit);
      wrap.appendChild(bDel);
      td.appendChild(wrap);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }

  function openExtraModal(existing, idx) {
    var isNew = !existing;
    var ex = existing ? JSON.parse(JSON.stringify(existing)) : {
      tag: "",
      protocol: "vless-reality",
      listen_port: 2443,
      uuid: genUUID(),
      path: "",
      domain: "",
      reality_sni: "www.apple.com",
      reality_dest: "www.apple.com:443",
      reality_privkey: "",
      reality_pubkey: "",
      reality_shortid: "",
      socks_user: "",
      socks_pass: "",
      target_addr: "",
      target_port: 0,
      network: "tcp,udp",
      via_nginx: false
    };

    openModal(isNew ? "添加附加协议 (Option 55)" : "编辑: " + ex.tag, function (body) {
      function fld(lbl, el) {
        var l = make("label", "field mt");
        l.appendChild(make("span", "", lbl));
        el.classList.add("form-control");
        l.appendChild(el);
        body.appendChild(l);
        return el;
      }
      var fProto = make("select");
      ["vless-reality", "vless-xhttp", "vless-ws", "vmess-ws", "dokodemo", "socks5"].forEach(function (p) {
        var o = make("option", "", p); o.value = p;
        if (p === ex.protocol) { o.selected = true; }
        fProto.appendChild(o);
      });
      fld("协议", fProto);
      var fTag = fld("Tag (留空自动生成)", make("input")); fTag.value = ex.tag || "";
      var fPort = fld("监听端口", make("input")); fPort.type = "number"; fPort.value = ex.listen_port || 2443;
      var fUUID = fld("UUID (Reality/XHTTP/WS)", make("input")); fUUID.value = ex.uuid || "";
      var fDom = fld("域名/SNI (XHTTP/WS 可选)", make("input")); fDom.value = ex.domain || "";
      var fPath = fld("Path (XHTTP/WS 留空自动派生)", make("input")); fPath.value = ex.path || "";
      var fVN = make("input"); fVN.type = "checkbox"; fVN.checked = !!ex.via_nginx;
      var vnLbl = make("label", "check-row mt"); vnLbl.appendChild(fVN); vnLbl.appendChild(document.createTextNode(" 经 Nginx 前置代理 (via_nginx)"));
      body.appendChild(vnLbl);

      var fRSNI = fld("Reality SNI", make("input")); fRSNI.value = ex.reality_sni || "www.apple.com";
      var fRDest = fld("Reality Dest (host:port)", make("input")); fRDest.value = ex.reality_dest || "www.apple.com:443";
      var fSU = fld("SOCKS5 用户名", make("input")); fSU.value = ex.socks_user || "";
      var fSP = fld("SOCKS5 密码", make("input")); fSP.type = "password"; fSP.value = ex.socks_pass || "";
      var fTAddr = fld("Dokodemo 目标主机", make("input")); fTAddr.value = ex.target_addr || "";
      var fTPort = fld("Dokodemo 目标端口", make("input")); fTPort.type = "number"; fTPort.value = ex.target_port || 0;
      var fNet = make("select");
      ["tcp,udp", "tcp", "udp"].forEach(function (n) { var o = make("option", "", n); o.value = n; if (n === (ex.network || "tcp,udp")) { o.selected = true; } fNet.appendChild(o); });
      fld("Dokodemo 网络", fNet);

      function updateFields() {
        var p = fProto.value;
        var isTLS = p === "vless-xhttp" || p === "vless-ws" || p === "vmess-ws";
        fUUID.parentElement.classList.toggle("hidden", p === "socks5" || p === "dokodemo");
        fDom.parentElement.classList.toggle("hidden", !isTLS);
        fPath.parentElement.classList.toggle("hidden", !isTLS);
        vnLbl.classList.toggle("hidden", !isTLS);
        fRSNI.parentElement.classList.toggle("hidden", p !== "vless-reality");
        fRDest.parentElement.classList.toggle("hidden", p !== "vless-reality");
        fSU.parentElement.classList.toggle("hidden", p !== "socks5");
        fSP.parentElement.classList.toggle("hidden", p !== "socks5");
        fTAddr.parentElement.classList.toggle("hidden", p !== "dokodemo");
        fTPort.parentElement.classList.toggle("hidden", p !== "dokodemo");
        fNet.parentElement.classList.toggle("hidden", p !== "dokodemo");
      }
      fProto.addEventListener("change", updateFields);
      updateFields();

      var b = make("button", "btn btn-primary mt", "确认");
      b.type = "button";
      b.addEventListener("click", function () {
        var p = fProto.value;
        var portNum = Number(fPort.value);
        if (!portNum) { showToast("端口无效", true); return; }
        var tag = fTag.value.trim() || ("inbound-" + p.replace("vless-", "") + "-" + portNum);
        var next = {
          tag: tag,
          protocol: p,
          listen_port: portNum,
          uuid: fUUID.value.trim(),
          path: fPath.value.trim(),
          domain: fDom.value.trim(),
          via_nginx: fVN.checked,
          reality_sni: fRSNI.value.trim(),
          reality_dest: fRDest.value.trim(),
          reality_privkey: ex.reality_privkey || "",
          reality_pubkey: ex.reality_pubkey || "",
          reality_shortid: ex.reality_shortid || "",
          socks_user: fSU.value,
          socks_pass: fSP.value,
          target_addr: fTAddr.value.trim(),
          target_port: Number(fTPort.value || 0),
          network: fNet.value
        };
        currentState.extra_inbounds = currentState.extra_inbounds || [];
        if (isNew) { currentState.extra_inbounds.push(next); }
        else { currentState.extra_inbounds[idx] = next; }
        renderExtraTable();
        closeModal();
      });
      body.appendChild(b);
    });
  }

  function collectRoutingFromUI() {
    var c = currentState.client;
    c.routing.divert.enabled = $("divert-enabled").checked;
    c.routing.divert.node_id = $("divert-node").value;
    c.routing.divert.chn_proxy_lan_ips = splitList($("divert-chn-lan").value);
    c.routing.divert.global_proxy_lan_ips = splitList($("divert-global-lan").value);
    c.routing.divert.direct_lan_ips = splitList($("divert-direct-lan").value);

    var sm = {};
    document.querySelectorAll("[data-nodesm-svc]").forEach(function (sel) {
      if (sel.value) { sm[sel.getAttribute("data-nodesm-svc")] = sel.value; }
    });
    c.routing.service_map = sm;
    c.routing.apple_node_id = $("apple-node").value;
    c.routing.steam_proxy = $("steam-proxy").checked;

    c.routing.custom.enabled = $("custom-enabled").checked;
    c.routing.custom.node_id = $("custom-node").value;
    c.routing.custom.domains = splitList($("custom-domains").value);
    c.routing.custom.ips = splitList($("custom-ips").value);
  }

  function collectDNSFromUI() {
    var d = currentState.client.dns;
    d.block_ads = $("dns-block-ads").checked;
    d.block_external_53 = $("dns-block53").checked;
    currentState.system.enable_ipv6 = $("dns-ipv6").checked;
    currentState.system.auto_update_rules = $("dns-auto-rules").checked;
    d.china_servers = splitList($("dns-china").value);
    d.doh_servers = splitList($("dns-doh").value);
    var hosts = {};
    splitList($("dns-hosts").value).forEach(function (line) {
      var parts = line.split(/[=\s]+/).filter(Boolean);
      if (parts.length >= 2) { hosts[parts[0]] = parts[1]; }
    });
    d.hosts = hosts;
    d.whitelist_domains = splitList($("dns-white-dom").value);
    d.blacklist_domains = splitList($("dns-black-dom").value);
    d.whitelist_ips = splitList($("dns-white-ip").value);
    d.blacklist_ips = splitList($("dns-black-ip").value);
  }

  function collectForwardFromUI() {
    var c = currentState.client;
    c.fwd0 = {
      enabled: $("fwd0-enabled").checked,
      protocol: $("fwd0-proto").value,
      port: Number($("fwd0-port").value || 9800),
      path: $("fwd0-path").value.trim(),
      uuids: splitList($("fwd0-uuids").value)
    };
    c.fwd1 = {
      enabled: $("fwd1-enabled").checked,
      protocol: $("fwd1-proto").value,
      port: Number($("fwd1-port").value || 9801),
      upstream_node_id: $("fwd1-upstream").value,
      path: $("fwd1-path").value.trim(),
      uuids: splitList($("fwd1-uuids").value)
    };
    c.rproxyc.enabled = $("rc-enabled").checked;
    c.rproxyc.tunnel_address = $("rc-domain").value.trim();
    c.rproxyc.tunnel_port = Number($("rc-port").value || 20000);
    c.rproxyc.tunnel_uuid = $("rc-uuid").value.trim();
    c.rproxyc.security = $("rc-security").value;
    c.rproxyc.server_name = $("rc-sni").value.trim();
    c.rproxyc.pinned_peer_cert_sha256 = $("rc-pin").value.trim();
    c.rproxyc.out_direct = $("rc-out-direct").checked;
  }

  function collectWGFromUI() {
    var wg = currentState.client.wireguard;
    wg.enabled = $("wg-enabled").checked;
    wg.endpoint_host = $("wg-endpoint").value.trim();
    wg.listen_port = Number($("wg-port").value || 51820);
    wg.subnet_cidr = $("wg-subnet").value.trim();
  }

  function collectDDNSFromUI() {
    var ddns = currentState.client.ddns;
    ddns.enabled = $("ddns-enabled").checked;
    ddns.domain = $("ddns-domain").value.trim();
    ddns.cf_email = $("ddns-email").value.trim();
    if ($("ddns-token").value.trim()) {
      ddns.cf_token = $("ddns-token").value.trim();
    }
    ddns.enable_ipv6 = $("ddns-v6").checked;
  }

  function collectServerFromUI() {
    var srv = currentState.server;
    srv.protocol = $("srv-proto").value;
    srv.tls_mode = $("srv-tls-mode").value;
    srv.domain = $("srv-domain").value.trim();
    srv.connect_host = $("srv-connect-host").value.trim();
    srv.listen_port = Number($("srv-port").value || 443);
    srv.public_port = Number($("srv-pub-port").value || 0);
    srv.path = $("srv-path").value.trim();
    srv.camouflage_dir = $("srv-camo-dir").value.trim();
    srv.uuids = splitList($("srv-uuids").value);
    srv.enable_doh = $("srv-enable-doh").checked;
  }

  function collectRproxySFromUI() {
    var rs = currentState.rproxys;
    rs.enabled = $("rs-enabled").checked;
    rs.domain = $("rs-domain").value.trim();
    rs.listen_port = Number($("rs-port").value || 20000);
    rs.security = $("rs-security").value;
    rs.uuids = splitList($("rs-uuids").value);
    rs.in_uuids = splitList($("rs-in-uuids").value);
  }

  async function saveAndApplyState(msg) {
    try {
      var res = await api("PUT", "/api/v1/state", currentState);
      currentState = res.state;
      currentSecrets = res.secrets || {};
      showToast(res.restarted_daemon ? "监听地址已变更，daemon 正在重启，请使用新端口刷新" : (msg || "已保存并应用"));
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  }

  async function runConnectivityProbe(silent) {
    var cnEl = $("kpi-conn-cn");
    var glEl = $("kpi-conn-global");
    cnEl.textContent = "国内线路: 探测中...";
    glEl.textContent = "国外线路: 探测中...";
    try {
      var res = await api("POST", "/api/v1/connectivity", { with_ips: true });
      var cn = res.cn || {};
      var gl = res.global || {};
      var cnDetail = cn.ok ? (cn.latency_ms + "ms" + (res.cn_ip ? (" · " + res.cn_ip) : "")) : (cn.error || "不通");
      var glDetail = gl.ok ? (gl.latency_ms + "ms" + (res.global_ip ? (" · " + res.global_ip) : "")) : (gl.error || "不通");
      cnEl.textContent = (cn.ok ? "✓ 国内 " : "✗ 国内 ") + cnDetail;
      glEl.textContent = (gl.ok ? "✓ 国外 " : "✗ 国外 ") + glDetail;
    } catch (e) {
      cnEl.textContent = "✗ 国内 探测失败";
      glEl.textContent = "✗ 国外 探测失败";
      if (!silent) { showToast(e.message, true); }
    }
  }

  async function runNodesProbe() {
    try {
      var res = await api("POST", "/api/v1/nodes/probe", {});
      (res.results || []).forEach(function (r) { probeResultsMap[r.node_id] = r; });
      renderNodesTable();
      renderOverviewNodes();
      showToast("节点测速完成");
    } catch (e) { showToast(e.message, true); }
  }

  async function doLogout() {
    try { await api("POST", "/api/v1/auth/logout", {}); } catch (_) {}
    csrfToken = "";
    clientAutoProbed = false;
    lastLogSeq = 0;
    if (logSource) { logSource.close(); logSource = null; }
    $("app-view").classList.add("hidden");
    $("login-view").classList.remove("hidden");
  }

  async function loadRulesStatus() {
    try {
      var res = await api("GET", "/api/v1/rules/status");
      var tbody = $("rules-tbody");
      clearEl(tbody);
      (res.files || []).forEach(function (f) {
        var tr = make("tr");
        tr.appendChild(make("td", "mono", f.name));
        tr.appendChild(make("td", "", f.exists ? "已就绪" : "缺失"));
        tr.appendChild(make("td", "", f.exists ? (Math.round(f.size_bytes / 1024) + " KB") : "-"));
        tr.appendChild(make("td", "mono", f.mod_time ? f.mod_time.slice(0, 19).replace("T", " ") : "-"));
        tbody.appendChild(tr);
      });
    } catch (_) {}
  }

  function connectLogs() {
    if (logSource) { logSource.close(); }
    var url = "/api/v1/logs/stream" + (lastLogSeq > 0 ? ("?since=" + encodeURIComponent(lastLogSeq)) : "");
    logSource = new EventSource(url);
    logSource.onmessage = function (ev) {
      try {
        var entry = JSON.parse(ev.data);
        if (entry.seq && entry.seq <= lastLogSeq) { return; }
        if (entry.seq && entry.seq > lastLogSeq) { lastLogSeq = entry.seq; }
        var box = $("log-box");
        var src = entry.subsystem || entry.source || "-";
        box.textContent += "[" + (entry.time || "").slice(11, 19) + "] " + (entry.level || "INFO") + " [" + src + "] " + (entry.message || "") + "\n";
        var lines = box.textContent.split("\n");
        if (lines.length > 501) {
          box.textContent = lines.slice(lines.length - 501).join("\n");
        }
        if (!logsPaused) { box.scrollTop = box.scrollHeight; }
      } catch (_) {}
    };
  }

  // Navigation & Navbar events
  document.querySelectorAll("#main-tabs .tab").forEach(function (t) {
    t.addEventListener("click", function () { setTab(t.getAttribute("data-tab")); });
  });
  $("nav-brand-link").addEventListener("click", function (ev) { ev.preventDefault(); setTab("overview"); });
  $("breadcrumb-home").addEventListener("click", function (ev) { ev.preventDefault(); setTab("overview"); });
  $("btn-sidebar-toggle").addEventListener("click", function () {
    $("app-view").classList.toggle("sidebar-toggled");
  });

  $("btn-mark-host").addEventListener("click", function () {
    openModal("备注本机", function (body) {
      var fld = make("label", "field");
      fld.appendChild(make("span", "", "本机备注名称 (system.hostname)"));
      var inp = make("input", "form-control");
      inp.type = "text";
      inp.placeholder = "例如 home-gateway";
      inp.value = (currentState && currentState.system && currentState.system.hostname) || "";
      fld.appendChild(inp);
      body.appendChild(fld);

      var btn = make("button", "btn btn-success mt", "保存");
      btn.type = "button";
      btn.addEventListener("click", async function () {
        try {
          await api("PUT", "/api/v1/system", { hostname: inp.value.trim() });
          showToast("本机备注已更新");
          closeModal();
          await refreshAll();
        } catch (e) { showToast(e.message, true); }
      });
      body.appendChild(btn);
      inp.focus();
    });
  });

  $("modal-close").addEventListener("click", closeModal);
  $("modal-backdrop").addEventListener("click", function (ev) {
    if (ev.target === $("modal-backdrop")) { closeModal(); }
  });

  $("login-form").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var errBox = $("login-error");
    errBox.classList.add("hidden");
    try {
      var res = await api("POST", "/api/v1/auth/login", { password: $("login-password").value });
      csrfToken = res.csrf_token || "";
      $("login-password").value = "";
      $("login-view").classList.add("hidden");
      $("app-view").classList.remove("hidden");
      await refreshAll();
      connectLogs();
    } catch (e) {
      errBox.textContent = e.message;
      errBox.classList.remove("hidden");
    }
  });

  $("btn-logout").addEventListener("click", doLogout);
  $("btn-sidebar-logout").addEventListener("click", doLogout);

  $("btn-apply-now").addEventListener("click", async function () {
    try {
      await api("POST", "/api/v1/apply", {});
      showToast("配置已应用");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-force-restart-apply").addEventListener("click", async function () {
    try {
      await api("POST", "/api/v1/apply?force=1&restart_all=1", {});
      showToast("已全量重启并应用配置");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-proxy-restart").addEventListener("click", async function () {
    try {
      var res = await api("POST", "/api/v1/proxy/restart", {});
      showToast("已重启: " + (res.restarted || []).join(", "));
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-proxy-stop").addEventListener("click", async function () {
    if (statusInfo && statusInfo.proxy_paused) {
      try {
        var resR = await api("POST", "/api/v1/proxy/restart", {});
        showToast("已恢复代理: " + (resR.restarted || []).join(", "));
        await refreshAll();
      } catch (e) { showToast(e.message, true); }
      return;
    }
    if (!window.confirm("确认关闭本地代理服务 (xray / nft)?")) { return; }
    try {
      var res = await api("POST", "/api/v1/proxy/stop", {});
      showToast("已关闭: " + (res.stopped || []).join(", "));
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-probe-conn").addEventListener("click", function (ev) {
    ev.stopPropagation();
    runConnectivityProbe(false);
  });
  $("kpi-conn-card").addEventListener("click", function () {
    runConnectivityProbe(false);
  });

  $("btn-jump-nodesm").addEventListener("click", function () {
    setTab("routing");
    $("card-nodesm").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $("btn-jump-nodecu").addEventListener("click", function () {
    setTab("routing");
    $("card-nodecu").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $("btn-jump-nodes").addEventListener("click", function () { setTab("nodes"); });

  $("btn-probe-nodes-overview").addEventListener("click", runNodesProbe);

  $("btn-server-main-qr").addEventListener("click", function () {
    showQRModal("服务端主节点", statusInfo && statusInfo.server_main_uri);
  });
  $("btn-server-doh-qr").addEventListener("click", function () {
    showQRModal("服务端 DoH 端点", statusInfo && statusInfo.doh_url);
  });

  $("btn-add-node").addEventListener("click", function () { openNodeModal(null, -1); });
  $("btn-probe-nodes").addEventListener("click", runNodesProbe);
  $("btn-save-nodes").addEventListener("click", function () {
    currentState.client.failover_enabled = $("failover-enabled").checked;
    saveAndApplyState("节点列表已保存并应用");
  });

  $("btn-nodesm-reset").addEventListener("click", function () {
    var activeID = currentState.client.active_node_id || (currentState.client.nodes[0] && currentState.client.nodes[0].id) || "";
    document.querySelectorAll("[data-nodesm-svc]").forEach(function (sel) { sel.value = activeID; });
  });
  $("btn-nodesm-clear").addEventListener("click", function () {
    document.querySelectorAll("[data-nodesm-svc]").forEach(function (sel) { sel.value = ""; });
  });
  $("btn-save-routing").addEventListener("click", function () {
    collectRoutingFromUI();
    saveAndApplyState("分流规则已保存并应用");
  });

  $("btn-probe-doh").addEventListener("click", async function () {
    var box = $("doh-probe-results");
    clearEl(box);
    box.appendChild(make("div", "text-muted", "正在探测 DoH 上游..."));
    try {
      var res = await api("POST", "/api/v1/nodes/probe", { include_doh: true });
      clearEl(box);
      (res.doh_results || []).forEach(function (r) {
        var el = make("div", "conn-box");
        el.appendChild(make("div", "mono", r.url));
        el.appendChild(make("span", r.ok ? "status-badge ok mt" : "status-badge fail mt",
          r.ok ? ("正常 · " + r.latency_ms + " ms") : (r.error || "失败")));
        box.appendChild(el);
      });
    } catch (e) { clearEl(box); showToast(e.message, true); }
  });
  $("btn-save-dns").addEventListener("click", function () {
    collectDNSFromUI();
    saveAndApplyState("DNS 配置已保存并应用");
  });
  $("btn-refresh-rules-status").addEventListener("click", loadRulesStatus);
  $("btn-update-rules").addEventListener("click", async function () {
    try {
      await api("POST", "/api/v1/rules/update", { include_ads: $("rules-include-ads").checked });
      showToast("规则库热更新成功");
      await loadRulesStatus();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-fwd0-qr").addEventListener("click", function () { showQRModal("FWD0 分享链接", statusInfo && statusInfo.fwd0_uri); });
  $("btn-fwd1-qr").addEventListener("click", function () { showQRModal("FWD1 分享链接", statusInfo && statusInfo.fwd1_uri); });
  $("btn-client-add-relay").addEventListener("click", function () { openRelayModal($("client-relay-tbody")); });
  $("btn-rc-add-map").addEventListener("click", function () {
    openModal("添加 RproxyC 内网映射", function (body) {
      function fld(lbl, el) {
        var l = make("label", "field mt");
        l.appendChild(make("span", "", lbl));
        el.classList.add("form-control");
        l.appendChild(el);
        body.appendChild(l);
        return el;
      }
      var fSP = fld("公网监听端口 (ext_port)", make("input")); fSP.type = "number"; fSP.value = "18080";
      var fCH = fld("内网目标主机 (int_ip)", make("input")); fCH.value = "127.0.0.1";
      var fCP = fld("内网目标端口 (int_port)", make("input")); fCP.type = "number"; fCP.value = "80";
      var fPr = make("select"); ["tcp", "udp", "tcp,udp"].forEach(function (p) { var o = make("option", "", p); o.value = p; fPr.appendChild(o); }); fld("协议", fPr);
      var b = make("button", "btn btn-primary mt", "加入映射");
      b.type = "button";
      b.addEventListener("click", function () {
        currentState.client.rproxyc.mappings = currentState.client.rproxyc.mappings || [];
        currentState.client.rproxyc.mappings.push({
          ext_port: Number(fSP.value),
          int_ip: fCH.value.trim(),
          int_port: Number(fCP.value),
          proto: fPr.value
        });
        renderRproxyCMappings();
        closeModal();
      });
      body.appendChild(b);
    });
  });
  $("btn-save-forward").addEventListener("click", function () {
    collectForwardFromUI();
    saveAndApplyState("转发与 RproxyC 已保存并应用");
  });

  $("btn-wg-regen-server").addEventListener("click", async function () {
    if (!window.confirm("重新生成服务端密钥将导致现有客户端配置失效，确认继续？")) { return; }
    try {
      await api("POST", "/api/v1/wireguard/regen-server", {});
      showToast("服务端 WireGuard 密钥已更新");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-wg-add-peer").addEventListener("click", async function () {
    var name = $("wg-peer-name").value.trim();
    if (!name) { showToast("请输入 Peer 名称", true); return; }
    try {
      var payload = {
        name: name,
        endpoint_host: $("wg-endpoint").value.trim(),
        listen_port: Number($("wg-port").value || 51820),
        subnet_cidr: $("wg-subnet").value.trim()
      };
      await api("POST", "/api/v1/wireguard/peers", payload);
      $("wg-peer-name").value = "";
      showToast("已添加 WireGuard Peer " + name);
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-save-wg").addEventListener("click", function () {
    collectWGFromUI();
    saveAndApplyState("WireGuard 配置已保存并应用");
  });

  $("btn-save-ddns").addEventListener("click", function () {
    collectDDNSFromUI();
    saveAndApplyState("DDNS 配置已保存并应用");
  });
  $("btn-ddns-sync").addEventListener("click", async function () {
    try {
      var res = await api("POST", "/api/v1/ddns/sync", {});
      var s = res.sync || {};
      showToast("DDNS 同步完成 (" + (s.ipv4 || "-") + " / " + (s.ipv6 || "-") + ")");
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-ddns-check-ips").addEventListener("click", async function () {
    try {
      var res = await api("POST", "/api/v1/connectivity", { with_ips: true });
      $("ddns-ip-result").textContent = "本机直连 IPv4: " + (res.cn_ip || "未知") + " | 代理出口 IP: " + (res.global_ip || "未知");
    } catch (e) { showToast(e.message, true); }
  });

  // Server / Landing / Relay handlers
  $("btn-srv-gen-uuid").addEventListener("click", function () {
    var cur = splitList($("srv-uuids").value);
    cur.push(genUUID());
    $("srv-uuids").value = cur.join("\n");
  });
  $("btn-save-server").addEventListener("click", function () {
    collectServerFromUI();
    saveAndApplyState("服务端主入站已保存并应用");
  });
  $("btn-add-socks5").addEventListener("click", function () { openSocks5Modal(null, -1); });
  $("btn-save-socks5").addEventListener("click", function () { saveAndApplyState("SOCKS5 出口配置已保存并应用"); });
  $("btn-add-extra").addEventListener("click", function () { openExtraModal(null, -1); });
  $("btn-disable-all-extra").addEventListener("click", function () {
    currentState.extra_inbounds = [];
    renderExtraTable();
  });
  $("btn-save-extra").addEventListener("click", function () { saveAndApplyState("附加协议配置已保存并应用"); });

  $("btn-srv-add-relay").addEventListener("click", function () { openRelayModal($("srv-relay-tbody")); });
  $("btn-rs-add-map").addEventListener("click", function () {
    openModal("添加 RproxyS 公网端口映射", function (body) {
      function fld(lbl, el) {
        var l = make("label", "field mt");
        l.appendChild(make("span", "", lbl));
        el.classList.add("form-control");
        l.appendChild(el);
        body.appendChild(l);
        return el;
      }
      var fP = fld("公网监听端口", make("input")); fP.type = "number"; fP.value = "18080";
      var fPr = make("select"); ["tcp", "udp", "tcp,udp"].forEach(function (p) { var o = make("option", "", p); o.value = p; fPr.appendChild(o); }); fld("协议", fPr);
      var b = make("button", "btn btn-primary mt", "加入映射");
      b.type = "button";
      b.addEventListener("click", function () {
        currentState.rproxys.mappings = currentState.rproxys.mappings || [];
        currentState.rproxys.mappings.push({ port: Number(fP.value), proto: fPr.value });
        renderRproxySMappings();
        closeModal();
      });
      body.appendChild(b);
    });
  });
  $("btn-save-relay-rproxys").addEventListener("click", function () {
    collectRproxySFromUI();
    saveAndApplyState("端口转发与 RproxyS 已保存并应用");
  });

  // System / Cert / Backup / Migrate
  $("btn-cert-issue").addEventListener("click", async function () {
    try {
      await api("POST", "/api/v1/cert/issue", {
        mode: $("cert-mode").value,
        domain: $("cert-domain").value.trim(),
        cf_email: $("cert-cf-email").value.trim(),
        cf_token: $("cert-cf-token").value.trim(),
        webroot: $("cert-webroot").value.trim(),
        auto_renew: $("cert-auto-renew").checked
      });
      showToast("ACME 证书签发并加载成功");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-cert-self-sign").addEventListener("click", async function () {
    try {
      await api("POST", "/api/v1/cert/self-sign", { cn: $("cert-domain").value.trim() || "localhost", force: true });
      showToast("已重新生成自签证书");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-cert-import").addEventListener("click", async function () {
    try {
      await api("POST", "/api/v1/cert/import", {
        cert_pem: $("cert-imp-pem").value,
        key_pem: $("cert-imp-key").value,
        allow_self_signed: $("cert-imp-allow-self").checked
      });
      showToast("证书导入并热加载完成");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-backup-download").addEventListener("click", function () {
    window.location.href = "/api/v1/backup";
  });
  $("restore-file").addEventListener("change", function (ev) {
    var f = ev.target.files && ev.target.files[0];
    if (!f) { return; }
    var reader = new FileReader();
    reader.onload = function () { $("restore-json").value = String(reader.result || ""); };
    reader.readAsText(f);
  });
  $("btn-restore-v3").addEventListener("click", async function () {
    try {
      var res = await api("POST", "/api/v1/migrate", {
        kind: "v3_state",
        raw_json: $("restore-json").value,
        apply: $("restore-apply").checked
      });
      showToast("备份恢复成功 (" + (res.notes || []).length + " 提示)");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-migrate").addEventListener("click", async function () {
    try {
      var res = await api("POST", "/api/v1/migrate", {
        kind: $("mig-kind").value,
        path: $("mig-path").value.trim(),
        raw_json: $("mig-raw").value,
        apply: $("mig-apply").checked
      });
      showToast("导入成功 (" + (res.notes || []).length + " 条迁移提示)");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-save-system").addEventListener("click", function () {
    currentState.system.hostname = $("sys-hostname").value.trim();
    currentState.system.auto_update_core = $("sys-auto-update-core").checked;
    currentState.auth.listen_addr = $("auth-listen").value.trim() || defaultListenAddrForRole(currentState.role);
    saveAndApplyState("系统设置已保存并应用");
  });
  $("btn-update-core").addEventListener("click", async function () {
    try {
      await api("POST", "/api/v1/update", {
        component: $("upd-component").value,
        version: $("upd-version").value.trim()
      });
      showToast("组件更新完成");
      await refreshAll();
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-change-pw").addEventListener("click", async function () {
    try {
      var res = await api("POST", "/api/v1/auth/password", {
        current_password: $("pw-old").value,
        new_password: $("pw-new").value
      });
      csrfToken = res.csrf_token || csrfToken;
      $("pw-old").value = ""; $("pw-new").value = "";
      showToast("密码已更新");
    } catch (e) { showToast(e.message, true); }
  });
  $("btn-reboot").addEventListener("click", async function () {
    if (!window.confirm("确认立即重启主机？")) { return; }
    try {
      await api("POST", "/api/v1/system/reboot", {});
      showToast("已下发重启指令");
    } catch (e) { showToast(e.message, true); }
  });

  $("btn-logs-toggle").addEventListener("click", function () {
    logsPaused = !logsPaused;
    $("btn-logs-toggle").textContent = logsPaused ? "恢复滚动" : "暂停滚动";
  });
  $("btn-logs-clear").addEventListener("click", function () {
    $("log-box").textContent = "";
  });

  initSession();
})();
