/* global vis */
let report = [];
let selectedIndex = -1;
let network = null;

function $(id) { return document.getElementById(id); }
function setStatus(text) { $("status").textContent = text || ""; }

function setActiveTab(tab) {
  document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(x => x.classList.remove("active"));
  document.querySelector(`.tab[data-tab="${tab}"]`).classList.add("active");
  $(`tab-${tab}`).classList.add("active");
}

document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => setActiveTab(btn.getAttribute("data-tab")));
});

function renderAlertList() {
  const box = $("alertsList");
  if (!report.length) {
    box.innerHTML = `<div class="muted">暂无数据。</div>`;
    return;
  }

  box.innerHTML = report.map((x, idx) => {
    const t = (x.paths?.lateral_source?.[0]?.logon_time || x.timestamp_start || "").toString().slice(0, 19);
    const active = idx === selectedIndex ? "active" : "";
    return `
      <div class="alert-card ${active}" data-idx="${idx}">
        <div class="alert-top">
          <span class="badge badge-high">HIGH</span>
          <span class="alert-time">${t}</span>
        </div>
        <div class="alert-main"><b>${x.victim_ip || ""}</b></div>
        <div class="alert-sub">${(x.trigger_technique || "").toString().slice(0, 80)}</div>
      </div>
    `;
  }).join("");

  box.querySelectorAll(".alert-card").forEach(el => {
    el.addEventListener("click", () => pickReportIndex(parseInt(el.getAttribute("data-idx"))));
  });
}

function kvHTML(items) {
  return items.map(([k, v]) => `
    <div class="kv">
      <div class="k">${k}</div>
      <div class="v">${v ?? ""}</div>
    </div>
  `).join("");
}

function renderSummary(item) {
  if (!item) {
    $("summaryEmpty").style.display = "";
    $("summaryContent").style.display = "none";
    return;
  }
  $("summaryEmpty").style.display = "none";
  $("summaryContent").style.display = "";

  const p = item.paths || {};
  const pt = p.process_tree || {};
  const lat = p.lateral_source || [];
  const exf = p.exfiltration || [];
  const ap = item.attacker_profile || {};

  // 入口：优先用 lateral_source[0] 作为“入口线索”（mock/真实都能用）
  const entry = lat[0] || {};
  $("entryBody").innerHTML = kvHTML([
    ["source_ip", entry.source_ip || "-"],
    ["user", entry.compromised_user || "-"],
    ["time", entry.logon_time || "-"]
  ]);

  // 执行链
  const chain = Array.isArray(pt.execution_chain) ? pt.execution_chain.join(" → ") : "-";
  $("execBody").innerHTML = kvHTML([
    ["root_process", pt.root_process || "-"],
    ["cmdline", pt.root_cmd || "-"],
    ["execution_chain", chain]
  ]);

  // 横向（如果有多条来源就展示条数）
  $("lateralBody").innerHTML = lat.length
    ? kvHTML([["events", `${lat.length} 条`], ["sample", `${lat[0].source_ip || ""} -> ${item.victim_ip || ""}`]])
    : `<div class="muted">未发现横向登录来源（或当前数据未覆盖）。</div>`;

  // 外传
  $("exfilBody").innerHTML = exf.length
    ? kvHTML([
        ["file", exf[0].sensitive_file || "-"],
        ["process", exf[0].leaking_process || "-"],
        ["dest_ip", exf[0].destination_ip || "-"]
      ])
    : `<div class="muted">未发现外传路径（或当前数据未覆盖）。</div>`;

  // raw json
  $("rawJson").textContent = JSON.stringify(item, null, 2);

  // IOC tab
  const iocHtml = [];
  iocHtml.push(`<div class="panel-title">Hashes</div><pre>${JSON.stringify(ap.malware_hashes || [], null, 2)}</pre>`);
  iocHtml.push(`<div class="panel-title">Domains</div><pre>${JSON.stringify(ap.c2_domains || [], null, 2)}</pre>`);
  iocHtml.push(`<div class="panel-title">Threat Intel</div><pre>${JSON.stringify(ap.infrastructure_intelligence || [], null, 2)}</pre>`);
  iocHtml.push(`<div class="panel-title">APT Match</div><pre>${JSON.stringify(ap.suspected_apt || [], null, 2)}</pre>`);
  $("iocBox").innerHTML = iocHtml.join("");
}

function renderGraph(item) {
  const container = $("graph");
  $("graphDetail").textContent = "{}";
  container.innerHTML = "";

  if (!item || !item.vis_graph) {
    container.innerHTML = `<div class="muted" style="padding:12px;">无图数据</div>`;
    return;
  }

  const nodes = new vis.DataSet(item.vis_graph.nodes || []);
  const edges = new vis.DataSet(item.vis_graph.edges || []);

  const options = {
    interaction: { hover: true },
    physics: {
      stabilization: { iterations: 120 },
      solver: "forceAtlas2Based",
      forceAtlas2Based: { gravitationalConstant: -30, centralGravity: 0.01, springLength: 120 }
    },
    nodes: { shape: "dot", size: 14, font: { size: 14 } },
    edges: { arrows: { to: { enabled: true, scaleFactor: 0.7 } }, font: { align: "middle" } },
    groups: {
      AttackEvent: { color: { background: "#ffb3b3", border: "#ff6666" } },
      Technique: { color: { background: "#fff2cc", border: "#e6b800" } },
      VictimIP: { color: { background: "#ddeeff", border: "#6699ff" } },
      SourceIP: { color: { background: "#e6ffe6", border: "#33aa33" } },
      ExternalIP: { color: { background: "#ffe6e6", border: "#cc0000" } },
      Process: { color: { background: "#eaeaea", border: "#666666" } },
      File: { color: { background: "#f0e6ff", border: "#8a63d2" } },
      Domain: { color: { background: "#e6f7ff", border: "#00a3cc" } },
      User: { color: { background: "#ffffff", border: "#333333" } }
    }
  };

  network = new vis.Network(container, { nodes, edges }, options);

  network.once("stabilizationIterationsDone", function() {
    network.setOptions({ physics: false }); // 稳定后停止抖动，更像产品
  });

  network.on("click", function(params) {
    if (params.nodes?.length) {
      $("graphDetail").textContent = JSON.stringify(nodes.get(params.nodes[0]), null, 2);
    } else if (params.edges?.length) {
      $("graphDetail").textContent = JSON.stringify(edges.get(params.edges[0]), null, 2);
    }
  });
}

function renderTimeline(item) {
  const box = $("timelineBox");
  $("timelineDetail").textContent = "{}";

  const tl = item?.timeline || [];
  if (!tl.length) {
    box.innerHTML = `<div class="muted">暂无时间线数据（mock 数据可以补 timeline 字段）。</div>`;
    return;
  }

  box.innerHTML = `
    <table class="tb-list" style="width:100%; border-collapse:collapse;">
      <thead><tr><th>time</th><th>source</th><th>event_type</th><th>summary</th></tr></thead>
      <tbody>
        ${tl.map((x, idx) => `
          <tr data-tl="${idx}" style="cursor:pointer">
            <td style="border-bottom:1px solid #eee; padding:6px 4px;">${(x.time||"").toString().slice(0,19)}</td>
            <td style="border-bottom:1px solid #eee; padding:6px 4px;">${x.source||""}</td>
            <td style="border-bottom:1px solid #eee; padding:6px 4px;">${x.event_type||""}</td>
            <td style="border-bottom:1px solid #eee; padding:6px 4px;">${x.summary||""}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;

  box.querySelectorAll("tr[data-tl]").forEach(tr => {
    tr.addEventListener("click", () => {
      const idx = parseInt(tr.getAttribute("data-tl"));
      $("timelineDetail").textContent = JSON.stringify(tl[idx], null, 2);
    });
  });
}

function pickReportIndex(i) {
  selectedIndex = i;
  renderAlertList();

  const item = report[i];
  renderSummary(item);
  renderGraph(item);
  renderTimeline(item);
}

async function analyze() {
  const mockMode = $("chkMock").checked;
  const useCache = $("chkCache").checked;

  setStatus("分析中...");
  const resp = await fetch(window.__TRACEBACK_API__.analyze, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mock_mode: mockMode, use_cache: useCache })
  });
  const data = await resp.json();

  if (!data.ok) {
    setStatus(`分析失败：${data.error || "unknown"}`);
    report = [];
    selectedIndex = -1;
    renderAlertList();
    renderSummary(null);
    renderGraph(null);
    renderTimeline(null);
    return;
  }

  report = data.report || [];
  setStatus(`完成：report=${report.length}（mode=${data.mode || "unknown"}）`);

  if (report.length) {
    pickReportIndex(0);
  } else {
    renderAlertList();
    renderSummary(null);
    renderGraph(null);
    renderTimeline(null);
  }
}

async function refreshHighAlerts() {
  const mockMode = $("chkMock").checked;
  setStatus("加载列表中...");

  const url = window.__TRACEBACK_API__.high_alerts + (mockMode ? "?mock_mode=1" : "?mock_mode=0");
  const resp = await fetch(url);
  const data = await resp.json();

  if (!data.ok) {
    setStatus(`加载失败：${data.error || "unknown"}`);
    return;
  }

  // 这里仅刷新列表，不影响 report
  const items = data.items || [];
  setStatus(`列表=${items.length}（mode=${data.mode || "unknown"}）`);
}

$("btnAnalyze").addEventListener("click", analyze);
$("btnRefresh").addEventListener("click", refreshHighAlerts);

// 默认自动跑一次（你演示更方便）
analyze();