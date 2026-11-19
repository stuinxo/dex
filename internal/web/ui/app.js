(function () {
  "use strict";

  var appState = null;
  var statusInfo = null;
  var csrfToken = "";
  var logSource = null;

  function el(id) { return document.getElementById(id); }
  function clearNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }
  function make(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function showToast(msg, isErr) {
    var t = el("toast");
    t.textContent = msg;
    t.className = isErr ? "toast err" : "toast";
    setTimeout(function () { t.classList.add("hidden"); }, 4000);
  }

  function openModal(title, builderFn) {
    el("modal-title").textContent = title;
    var body = el("modal-body");
    clearNode(body);
    builderFn(body);
    el("modal-backdrop").classList.remove("hidden");
  }
  function closeModal() {
    el("modal-backdrop").classList.add("hidden");
  }

  async function apiFetch(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (opts.method && opts.method !== "GET" && csrfToken) {
      opts.headers["X-CSRF-Token"] = csrfToken;
    }
    if (opts.body && typeof opts.body === "object") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    var resp = await fetch(url, opts);
    var text = await resp.text();
    var data = null;
    try { data = JSON.parse(text); } catch (_) { data = { raw: text }; }
    if (resp.status === 401 && url !== "/api/v1/auth/login") {
      showLogin();
      throw new Error("未登录或会话已过期");
    }
    if (!resp.ok) {
      throw new Error((data && data.error) ? data.error : ("HTTP " + resp.status));
    }
    return data;
  }

  function showLogin() {
    if (logSource) { logSource.close(); logSource = null; }
    el("app-view").classList.add("hidden");
    el("login-view").classList.remove("hidden");
  }

  function showApp() {
    el("login-view").classList.add("hidden");
    el("app-view").classList.remove("hidden");
    startLogStream();
  }

  function linesToArr(txt) {
    return txt.split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
  }
  function arrToLines(arr) {
    return Array.isArray(arr) ? arr.join("\n") : "";
  }

  function fillNodeSelect(selectEl, nodes, selectedId) {
    clearNode(selectEl);
    var emptyOpt = make("option", "", "默认 / 直连");
    emptyOpt.value = "";
    selectEl.appendChild(emptyOpt);
    (nodes || []).forEach(function (n) {
      var opt = make("option", "", (n.name || n.address) + " (" + n.protocol + ")");
      opt.value = n.id;
      selectEl.appendChild(opt);
    });
    selectEl.value = selectedId || "";
  }

  function renderOverview() {
    if (!statusInfo || !appState) return;
    el("badge-version").textContent = statusInfo.version || "v3";
    el("badge-role").textContent = statusInfo.role || appState.role;
    el("header-host").textContent = (statusInfo.hostname || "") + " (" + (statusInfo.mem_mb || 0) + " MiB)";

    var sg = el("services-grid");
    clearNode(sg);
    var svcs = statusInfo.services || {};
    Object.keys(svcs).sort().forEach(function (k) {
      var pill = make("div", "svc-pill");
      pill.appendChild(make("span", "", k));
      var dot = make("span", svcs[k] ? "dot on" : "dot");
      pill.appendChild(dot);
      sg.appendChild(pill);
    });

    var sum = el("system-summary");
    clearNode(sum);
    var rows = [
      ["运行角色", appState.role],
      ["Init / 容器", (statusInfo.init_system || "-") + (statusInfo.is_container ? " (Container)" : "")],
      ["运行时长", (statusInfo.uptime_sec || 0) + " s"],
      ["当前激活节点", statusInfo.active_node_id || "-"]
    ];
    if (statusInfo.server_main_uri) rows.push(["服务端链接", statusInfo.server_main_uri]);
    rows.forEach(function (pair) {
      var r = make("div", "kv-row");
      r.appendChild(make("span", "muted", pair[0]));
      r.appendChild(make("span", "", pair[1]));
      sum.appendChild(r);
    });

    var qn = el("quick-nodes");
    clearNode(qn);
    (appState.client.nodes || []).forEach(function (n) {
      var c = make("div", "node-card" + (n.id === appState.client.active_node_id ? " active" : ""));
      c.appendChild(make("div", "", n.name || n.id));
      c.appendChild(make("div", "muted", n.protocol + " · " + n.address + ":" + n.port));
      var lat = make("div", "muted", "");
      lat.id = "probe-" + n.id;
      c.appendChild(lat);
      c.addEventListener("click", async function () {
        try {
          await apiFetch("/api/v1/nodes/select", { method: "POST", body: { node_id: n.id } });
          appState.client.active_node_id = n.id;
          showToast("已切换主节点：" + (n.name || n.id));
          await refreshAll();
        } catch (e) { showToast(e.message, true); }
      });
      qn.appendChild(c);
    });
  }

  function renderNodesAndRouting() {
    var c = appState.client;
    el("chk-failover").checked = !!c.failover_enabled;

    var tbody = el("nodes-tbody");
    clearNode(tbody);
    (c.nodes || []).forEach(function (n, idx) {
      var tr = document.createElement("tr");
      tr.appendChild(make("td", "", n.name || n.id));
      tr.appendChild(make("td", "", n.protocol));
      tr.appendChild(make("td", "", n.address + ":" + n.port));
      tr.appendChild(make("td", "", n.tls_sni || n.address));
      var tdAct = make("td", "row-gap");
      var btnQR = make("button", "btn", "链接/QR");
      btnQR.addEventListener("click", function () {
        var uri = (statusInfo && statusInfo.node_uris && statusInfo.node_uris[n.id]) || "";
        openModal(n.name || n.id, function (body) {
          if (uri) {
            var wrap = make("div", "qr-wrap");
            wrap.appendChild(window.DexQR.createSVG(uri, 210));
            body.appendChild(wrap);
            var ta = make("textarea");
            ta.rows = 3;
            ta.readOnly = true;
            ta.value = uri;
            body.appendChild(ta);
          } else {
            body.appendChild(make("p", "muted", "应用保存后可生成标准分享链接。"));
          }
        });
      });
      var btnDel = make("button", "btn danger", "删除");
      btnDel.addEventListener("click", function () {
        c.nodes.splice(idx, 1);
        renderNodesAndRouting();
      });
      tdAct.appendChild(btnQR);
      tdAct.appendChild(btnDel);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });

    // NodeSM 16 services + Apple + Steam
    var smGrid = el("nodesm-grid");
    clearNode(smGrid);
    var svcs = (statusInfo && statusInfo.node_sm_services) || [];
    var smMap = c.routing.service_map || {};
    svcs.forEach(function (svc) {
      var f = make("label", "field");
      f.appendChild(make("span", "", svc.toUpperCase()));
      var sel = document.createElement("select");
      fillNodeSelect(sel, c.nodes, smMap[svc] || "");
      sel.addEventListener("change", function () {
        if (!c.routing.service_map) c.routing.service_map = {};
        if (sel.value) c.routing.service_map[svc] = sel.value;
        else delete c.routing.service_map[svc];
      });
      f.appendChild(sel);
      smGrid.appendChild(f);
    });
    var fApple = make("label", "field");
    fApple.appendChild(make("span", "", "APPLE (默认直连)"));
    var selApple = document.createElement("select");
    fillNodeSelect(selApple, c.nodes, c.routing.apple_node_id || "");
    selApple.addEventListener("change", function () { c.routing.apple_node_id = selApple.value; });
    fApple.appendChild(selApple);
    smGrid.appendChild(fApple);

    var fSteam = make("label", "inline-check");
    var chkSteam = document.createElement("input");
    chkSteam.type = "checkbox";
    chkSteam.checked = !!c.routing.steam_proxy;
    chkSteam.addEventListener("change", function () { c.routing.steam_proxy = chkSteam.checked; });
    fSteam.appendChild(chkSteam);
    fSteam.appendChild(make("span", "", "Steam 走代理（取消则直连）"));
    smGrid.appendChild(fSteam);

    // NodeDT & NodeCU
    var dt = c.routing.divert || {};
    el("chk-nodedt").checked = !!dt.enabled;
    fillNodeSelect(el("sel-nodedt-node"), c.nodes, dt.node_id || "");
    el("txt-nodedt-global").value = arrToLines(dt.global_proxy_lan_ips);
    el("txt-nodedt-direct").value = arrToLines(dt.direct_lan_ips);

    var cu = c.routing.custom || {};
    el("chk-nodecu").checked = !!cu.enabled;
    fillNodeSelect(el("sel-nodecu-node"), c.nodes, cu.node_id || "");
    el("txt-nodecu-domains").value = arrToLines(cu.domains);
    el("txt-nodecu-ips").value = arrToLines(cu.ips);
  }

  function renderDNSAndLists() {
    var d = appState.client.dns || {};
    el("chk-block-ads").checked = !!d.block_ads;
    el("chk-enable-ipv6").checked = !!appState.system.enable_ipv6;
    el("txt-dns-china").value = arrToLines(d.china_servers);
    el("txt-dns-doh").value = arrToLines(d.doh_servers);
    var hostLines = [];
    Object.keys(d.hosts || {}).sort().forEach(function (k) {
      hostLines.push(k + " " + d.hosts[k]);
    });
    el("txt-dns-hosts").value = hostLines.join("\n");
    el("txt-list-b-dom").value = arrToLines(d.blacklist_domains);
    el("txt-list-w-dom").value = arrToLines(d.whitelist_domains);
    el("txt-list-b-ip").value = arrToLines(d.blacklist_ips);
    el("txt-list-w-ip").value = arrToLines(d.whitelist_ips);
  }

  function renderForwardAndRproxy() {
    var c = appState.client;
    el("chk-fwd0").checked = !!c.fwd0.enabled;
    el("inp-fwd0-port").value = c.fwd0.port || "";
    el("inp-fwd0-path").value = c.fwd0.path || "";
    el("txt-fwd0-uuids").value = arrToLines(c.fwd0.uuids);

    el("chk-fwd1").checked = !!c.fwd1.enabled;
    el("inp-fwd1-port").value = c.fwd1.port || "";
    el("inp-fwd1-path").value = c.fwd1.path || "";
    el("txt-fwd1-uuids").value = arrToLines(c.fwd1.uuids);
    fillNodeSelect(el("sel-fwd1-node"), c.nodes, c.fwd1.upstream_node_id || "");

    el("chk-rproxyc").checked = !!c.rproxyc.enabled;
    el("inp-rpc-addr").value = c.rproxyc.tunnel_address || "";
    el("inp-rpc-port").value = c.rproxyc.tunnel_port || "";
    el("inp-rpc-uuid").value = c.rproxyc.tunnel_uuid || "";
    el("txt-rpc-maps").value = (c.rproxyc.mappings || []).map(function (m) {
      return m.ext_port + " " + (m.proto || "tcp") + " " + m.int_ip + ":" + m.int_port;
    }).join("\n");

    var rbody = el("relay-tbody");
    clearNode(rbody);
    ((appState.relay && appState.relay.forwards) || []).forEach(function (fwd, idx) {
      var tr = document.createElement("tr");
      tr.appendChild(make("td", "", String(fwd.listen_port)));
      tr.appendChild(make("td", "", fwd.target_host + ":" + fwd.target_port));
      tr.appendChild(make("td", "", fwd.proto));
      tr.appendChild(make("td", "", fwd.engine));
      var td = make("td", "");
      var del = make("button", "btn danger", "删除");
      del.addEventListener("click", function () {
        appState.relay.forwards.splice(idx, 1);
        renderForwardAndRproxy();
      });
      td.appendChild(del);
      tr.appendChild(td);
      rbody.appendChild(tr);
    });
  }

  function renderWGAndDDNS() {
    var wg = appState.client.wireguard || {};
    el("chk-wg-enabled").checked = !!wg.enabled;
    el("inp-wg-host").value = wg.endpoint_host || "";
    el("inp-wg-port").value = wg.listen_port || 51820;
    el("inp-wg-subnet").value = wg.subnet_cidr || "172.16.66.1/24";

    var tbody = el("wg-peers-tbody");
    clearNode(tbody);
    (wg.peers || []).forEach(function (p, idx) {
      var tr = document.createElement("tr");
      tr.appendChild(make("td", "", p.name));
      tr.appendChild(make("td", "", p.ip));
      var td = make("td", "row-gap");
      var btnCfg = make("button", "btn", "配置 / QR");
      btnCfg.addEventListener("click", async function () {
        try {
          var resp = await fetch("/api/v1/wireguard/peers/" + encodeURIComponent(p.name) + "/config");
          var cfg = await resp.text();
          openModal("WireGuard Peer: " + p.name, function (body) {
            var wrap = make("div", "qr-wrap");
            wrap.appendChild(window.DexQR.createSVG(cfg, 220));
            body.appendChild(wrap);
            var ta = make("textarea");
            ta.rows = 10;
            ta.readOnly = true;
            ta.value = cfg;
            body.appendChild(ta);
          });
        } catch (e) { showToast(e.message, true); }
      });
      var btnDel = make("button", "btn danger", "删除");
      btnDel.addEventListener("click", function () {
        wg.peers.splice(idx, 1);
        renderWGAndDDNS();
      });
      td.appendChild(btnCfg);
      td.appendChild(btnDel);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });

    var ddns = appState.client.ddns || {};
    el("chk-ddns-enabled").checked = !!ddns.enabled;
    el("chk-ddns-v6").checked = !!ddns.enable_ipv6;
    el("inp-ddns-domain").value = ddns.domain || "";
    el("inp-ddns-token").value = ddns.cf_token || "";
  }

  function renderSystem() {
    var box = el("cert-info");
    clearNode(box);
    var cert = statusInfo && statusInfo.cert;
    if (!cert) {
      box.appendChild(make("div", "muted", "暂无已安装证书"));
      return;
    }
    var rows = [
      ["Common Name", cert.common_name || "-"],
      ["SAN 域名", (cert.sans || []).join(", ")],
      ["到期时间", cert.not_after || "-"],
      ["类型", cert.self_signed ? "自签证书" : (cert.chain_valid ? "受信任证书链" : "链未完整校验")]
    ];
    rows.forEach(function (pair) {
      var r = make("div", "kv-row");
      r.appendChild(make("span", "muted", pair[0]));
      r.appendChild(make("span", "", pair[1]));
      box.appendChild(r);
    });
  }

  function collectFormIntoState() {
    if (!appState) return;
    var c = appState.client;
    c.failover_enabled = el("chk-failover").checked;
    c.routing.divert.enabled = el("chk-nodedt").checked;
    c.routing.divert.node_id = el("sel-nodedt-node").value;
    c.routing.divert.global_proxy_lan_ips = linesToArr(el("txt-nodedt-global").value);
    c.routing.divert.direct_lan_ips = linesToArr(el("txt-nodedt-direct").value);

    c.routing.custom.enabled = el("chk-nodecu").checked;
    c.routing.custom.node_id = el("sel-nodecu-node").value;
    c.routing.custom.domains = linesToArr(el("txt-nodecu-domains").value);
    c.routing.custom.ips = linesToArr(el("txt-nodecu-ips").value);

    c.dns.block_ads = el("chk-block-ads").checked;
    appState.system.enable_ipv6 = el("chk-enable-ipv6").checked;
    c.dns.china_servers = linesToArr(el("txt-dns-china").value);
    c.dns.doh_servers = linesToArr(el("txt-dns-doh").value);
    var hosts = {};
    linesToArr(el("txt-dns-hosts").value).forEach(function (line) {
      var parts = line.split(/\s+/);
      if (parts.length >= 2) hosts[parts[0]] = parts[1];
    });
    c.dns.hosts = hosts;
    c.dns.blacklist_domains = linesToArr(el("txt-list-b-dom").value);
    c.dns.whitelist_domains = linesToArr(el("txt-list-w-dom").value);
    c.dns.blacklist_ips = linesToArr(el("txt-list-b-ip").value);
    c.dns.whitelist_ips = linesToArr(el("txt-list-w-ip").value);

    c.fwd0.enabled = el("chk-fwd0").checked;
    c.fwd0.port = parseInt(el("inp-fwd0-port").value, 10) || 0;
    c.fwd0.path = el("inp-fwd0-path").value.trim();
    c.fwd0.uuids = linesToArr(el("txt-fwd0-uuids").value);

    c.fwd1.enabled = el("chk-fwd1").checked;
    c.fwd1.port = parseInt(el("inp-fwd1-port").value, 10) || 0;
    c.fwd1.path = el("inp-fwd1-path").value.trim();
    c.fwd1.uuids = linesToArr(el("txt-fwd1-uuids").value);
    c.fwd1.upstream_node_id = el("sel-fwd1-node").value;

    c.rproxyc.enabled = el("chk-rproxyc").checked;
    c.rproxyc.tunnel_address = el("inp-rpc-addr").value.trim();
    c.rproxyc.tunnel_port = parseInt(el("inp-rpc-port").value, 10) || 443;
    c.rproxyc.tunnel_uuid = el("inp-rpc-uuid").value.trim();
    c.rproxyc.mappings = linesToArr(el("txt-rpc-maps").value).map(function (line) {
      var ps = line.split(/\s+/);
      var hp = (ps[2] || "").split(":");
      return {
        ext_port: parseInt(ps[0], 10) || 0,
        proto: ps[1] || "tcp",
        int_ip: hp[0] || "",
        int_port: parseInt(hp[1], 10) || 0
      };
    });

    c.wireguard.enabled = el("chk-wg-enabled").checked;
    c.wireguard.endpoint_host = el("inp-wg-host").value.trim();
    c.wireguard.listen_port = parseInt(el("inp-wg-port").value, 10) || 51820;
    c.wireguard.subnet_cidr = el("inp-wg-subnet").value.trim();

    c.ddns.enabled = el("chk-ddns-enabled").checked;
    c.ddns.enable_ipv6 = el("chk-ddns-v6").checked;
    c.ddns.domain = el("inp-ddns-domain").value.trim();
    c.ddns.cf_token = el("inp-ddns-token").value.trim();
  }

  async function refreshAll() {
    var stRes = await apiFetch("/api/v1/status");
    var stateRes = await apiFetch("/api/v1/state");
    statusInfo = stRes;
    appState = stateRes.state;
    renderOverview();
    renderNodesAndRouting();
    renderDNSAndLists();
    renderForwardAndRproxy();
    renderWGAndDDNS();
    renderSystem();
  }

  function startLogStream() {
    if (logSource) logSource.close();
    var box = el("log-stream");
    logSource = new EventSource("/api/v1/logs/stream");
    logSource.onmessage = function (ev) {
      try {
        var entry = JSON.parse(ev.data);
        var line = "[" + entry.time + "] [" + entry.level + "] [" + entry.subsystem + "] " + entry.message + "\n";
        box.textContent += line;
        box.scrollTop = box.scrollHeight;
      } catch (_) {}
    };
  }

  function bindEvents() {
    el("modal-close").addEventListener("click", closeModal);

    document.querySelectorAll("#nav-tabs .tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        document.querySelectorAll("#nav-tabs .tab").forEach(function (b) { b.classList.remove("active"); });
        document.querySelectorAll(".tab-panel").forEach(function (p) { p.classList.remove("active"); });
        btn.classList.add("active");
        el("tab-" + btn.getAttribute("data-tab")).classList.add("active");
      });
    });

    el("login-form").addEventListener("submit", async function (ev) {
      ev.preventDefault();
      el("login-error").classList.add("hidden");
      try {
        var res = await apiFetch("/api/v1/auth/login", {
          method: "POST",
          body: { password: el("login-password").value }
        });
        csrfToken = res.csrf_token || "";
        el("login-password").value = "";
        showApp();
        await refreshAll();
      } catch (e) {
        el("login-error").textContent = e.message;
        el("login-error").classList.remove("hidden");
      }
    });

    el("btn-logout").addEventListener("click", async function () {
      try { await apiFetch("/api/v1/auth/logout", { method: "POST" }); } catch (_) {}
      csrfToken = "";
      showLogin();
    });

    el("btn-apply").addEventListener("click", async function () {
      try {
        collectFormIntoState();
        await apiFetch("/api/v1/state", { method: "PUT", body: appState });
        showToast("配置已验证并成功应用");
        await refreshAll();
      } catch (e) { showToast(e.message, true); }
    });

    el("btn-refresh-status").addEventListener("click", function () {
      refreshAll().catch(function (e) { showToast(e.message, true); });
    });

    el("btn-probe-all").addEventListener("click", async function () {
      try {
        var res = await apiFetch("/api/v1/nodes/probe", { method: "POST", body: {} });
        (res.results || []).forEach(function (r) {
          var target = el("probe-" + r.node_id);
          if (target) {
            target.textContent = r.healthy ? ("健康 " + r.latency_ms + "ms") : ("不可达 (" + (r.error || r.status_code) + ")");
          }
        });
        showToast("节点探活完成");
      } catch (e) { showToast(e.message, true); }
    });

    el("btn-add-node").addEventListener("click", function () {
      openModal("添加出站节点", function (body) {
        var fields = [
          ["name", "名称", "text", "新节点"],
          ["protocol", "协议 (vless-xhttp / vless-reality / vless-ws / vmess-ws / socks5)", "text", "vless-xhttp"],
          ["address", "服务器地址", "text", ""],
          ["port", "端口", "number", "443"],
          ["uuid", "UUID", "text", ""],
          ["tls_sni", "TLS SNI (可选)", "text", ""],
          ["path", "Path (可选)", "text", ""]
        ];
        var inputs = {};
        fields.forEach(function (f) {
          var lbl = make("label", "field");
          lbl.appendChild(make("span", "", f[1]));
          var inp = document.createElement("input");
          inp.type = f[2];
          inp.value = f[3];
          lbl.appendChild(inp);
          body.appendChild(lbl);
          inputs[f[0]] = inp;
        });
        var okBtn = make("button", "btn primary", "添加到列表（点击顶部 Apply 生效）");
        okBtn.addEventListener("click", function () {
          appState.client.nodes.push({
            id: "node-" + Date.now(),
            name: inputs.name.value.trim(),
            protocol: inputs.protocol.value.trim() || "vless-xhttp",
            address: inputs.address.value.trim(),
            port: parseInt(inputs.port.value, 10) || 443,
            uuid: inputs.uuid.value.trim(),
            tls_sni: inputs.tls_sni.value.trim(),
            path: inputs.path.value.trim()
          });
          if (!appState.client.active_node_id && appState.client.nodes.length > 0) {
            appState.client.active_node_id = appState.client.nodes[0].id;
          }
          renderNodesAndRouting();
          closeModal();
        });
        body.appendChild(okBtn);
      });
    });

    el("btn-add-relay").addEventListener("click", function () {
      openModal("添加端口转发规则", function (body) {
        var fields = [
          ["listen", "本机监听端口", "number", "10001"],
          ["target_host", "目标主机", "text", ""],
          ["target_port", "目标端口", "number", "443"],
          ["proto", "协议 (tcp / udp / tcp,udp)", "text", "tcp"],
          ["engine", "引擎 (nft / haproxy / xray)", "text", "nft"]
        ];
        var inputs = {};
        fields.forEach(function (f) {
          var lbl = make("label", "field");
          lbl.appendChild(make("span", "", f[1]));
          var inp = document.createElement("input");
          inp.type = f[2];
          inp.value = f[3];
          lbl.appendChild(inp);
          body.appendChild(lbl);
          inputs[f[0]] = inp;
        });
        var okBtn = make("button", "btn primary", "添加规则");
        okBtn.addEventListener("click", function () {
          if (!appState.relay) appState.relay = { forwards: [] };
          if (!appState.relay.forwards) appState.relay.forwards = [];
          appState.relay.forwards.push({
            id: "fwd-" + Date.now(),
            listen_port: parseInt(inputs.listen.value, 10) || 0,
            target_host: inputs.target_host.value.trim(),
            target_port: parseInt(inputs.target_port.value, 10) || 443,
            proto: inputs.proto.value.trim() || "tcp",
            engine: inputs.engine.value.trim() || "nft"
          });
          renderForwardAndRproxy();
          closeModal();
        });
        body.appendChild(okBtn);
      });
    });

    el("btn-add-wg-peer").addEventListener("click", async function () {
      var name = window.prompt("请输入新 WireGuard 客户端名称（例如 laptop）：", "peer-" + ((appState.client.wireguard.peers || []).length + 1));
      if (!name) return;
      try {
        await apiFetch("/api/v1/wireguard/peers", { method: "POST", body: { name: name } });
        showToast("已生成 WireGuard 客户端 " + name);
        await refreshAll();
      } catch (e) { showToast(e.message, true); }
    });

    el("btn-ddns-sync").addEventListener("click", async function () {
      try {
        var res = await apiFetch("/api/v1/ddns/sync", { method: "POST", body: {} });
        showToast("DDNS 同步成功: " + (res.sync && res.sync.ipv4 ? res.sync.ipv4 : "OK"));
      } catch (e) { showToast(e.message, true); }
    });

    el("btn-change-pw").addEventListener("click", async function () {
      try {
        var res = await apiFetch("/api/v1/auth/password", {
          method: "POST",
          body: { current_password: el("inp-pw-cur").value, new_password: el("inp-pw-new").value }
        });
        if (res.csrf_token) csrfToken = res.csrf_token;
        el("inp-pw-cur").value = "";
        el("inp-pw-new").value = "";
        showToast("登录密码已更新");
      } catch (e) { showToast(e.message, true); }
    });

    async function doMigrate(apply) {
      try {
        var res = await apiFetch("/api/v1/migrate", {
          method: "POST",
          body: {
            kind: el("sel-mig-kind").value,
            path: el("inp-mig-path").value.trim(),
            raw_json: el("txt-mig-json").value,
            apply: apply
          }
        });
        showToast("导入成功（" + (res.notes ? res.notes.length : 0) + " 条迁移说明）");
        await refreshAll();
      } catch (e) { showToast(e.message, true); }
    }
    el("btn-mig-import").addEventListener("click", function () { doMigrate(false); });
    el("btn-mig-apply").addEventListener("click", function () { doMigrate(true); });
    el("btn-clear-logs").addEventListener("click", function () { el("log-stream").textContent = ""; });
  }

  async function boot() {
    bindEvents();
    try {
      var sess = await apiFetch("/api/v1/auth/session");
      if (sess.authenticated) {
        csrfToken = sess.csrf_token || "";
        showApp();
        await refreshAll();
        return;
      }
    } catch (_) {}
    showLogin();
  }

  boot();
})();
