(function () {
  const startBtn = document.getElementById("lt-start-btn");
  const statusEl = document.getElementById("lt-status");
  const graphGrid = document.getElementById("lt-graph-grid");
  const timelineCanvas = document.getElementById("lt-timeline");

  if (!startBtn || !statusEl || !graphGrid || !timelineCanvas) {
    return;
  }

  const API_START = "/api/logontracer/start";
  const API_JOB = "/api/logontracer/job/";
  const API_GRAPH = "/api/logontracer/graph";
  const API_TIMELINE = "/api/logontracer/timeline";
  const API_SESSIONS = "/api/logontracer/sessions";
  const API_SESSION_EVENTS = "/api/logontracer/session_events";

  let pollTimer = null;
  let currentJobId = null;
  let cyInstances = [];
  let timelineChart = null;
  let sessionsTable = null;

  function setStatus(text, level) {
    statusEl.textContent = text;
    statusEl.classList.remove("ok", "error");
    if (level === "ok") statusEl.classList.add("ok");
    if (level === "error") statusEl.classList.add("error");
  }

  function clearViews() {
    cyInstances.forEach((instance) => instance.destroy());
    cyInstances = [];
    graphGrid.innerHTML = "";
    if (timelineChart) {
      timelineChart.destroy();
      timelineChart = null;
    }
    if (sessionsTable) {
      sessionsTable.destroy();
      sessionsTable = null;
      const tableBody = document.querySelector("#lt-sessions-table tbody");
      if (tableBody) tableBody.innerHTML = "";
    }
  }

  function readFilters() {
    const start = document.getElementById("lt-start").value;
    const end = document.getElementById("lt-end").value;
    const user = document.getElementById("lt-user").value;
    const srcIp = document.getElementById("lt-src-ip").value;
    const hostNames = readHostSelections();
    const bucket = document.getElementById("lt-bucket").value;
    return {
      start: start || null,
      end: end || null,
      user: user || null,
      src_ip: srcIp || null,
      host_names: hostNames.length ? hostNames : null,
      bucket: bucket || "hour",
    };
  }

  function readHostSelections() {
    const multi = document.getElementById("lt-host-multi");
    if (!multi) return [];
    const checked = multi.querySelectorAll("input[type=checkbox]:checked");
    return Array.from(checked)
      .map((item) => item.value)
      .filter((value) => value);
  }

  function initHostMultiSelect() {
    const multi = document.getElementById("lt-host-multi");
    if (!multi) return;
    const toggle = multi.querySelector(".lt-multi-toggle");
    const panel = multi.querySelector(".lt-multi-panel");
    const checkboxes = multi.querySelectorAll("input[type=checkbox]");
    if (!toggle || !panel) return;

    function updateLabel() {
      const selected = readHostSelections();
      if (!selected.length) {
        toggle.textContent = "选择主机";
        return;
      }
      if (selected.length <= 2) {
        toggle.textContent = selected.join(", ");
        return;
      }
      toggle.textContent = `已选 ${selected.length} 台主机`;
    }

    toggle.addEventListener("click", function (event) {
      event.stopPropagation();
      const isOpen = multi.classList.toggle("open");
      toggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });

    document.addEventListener("click", function (event) {
      if (!multi.contains(event.target)) {
        multi.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });

    checkboxes.forEach((box) => {
      box.addEventListener("change", updateLabel);
    });

    updateLabel();
  }

  function startAnalysis() {
    clearViews();
    const payload = readFilters();
    setStatus("Analysis started. Please wait...", "info");
    startBtn.disabled = true;

    fetch(API_START, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then((resp) => resp.json())
      .then((data) => {
        if (!data || !data.job_id) {
          setStatus("Failed to start job.", "error");
          startBtn.disabled = false;
          return;
        }
        currentJobId = data.job_id;
        pollJob(currentJobId);
      })
      .catch(() => {
        setStatus("Failed to start job.", "error");
        startBtn.disabled = false;
      });
  }

  function pollJob(jobId) {
    if (!jobId) return;
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
    fetch(API_JOB + encodeURIComponent(jobId))
      .then((resp) => resp.json())
      .then((data) => {
        if (!data || !data.status) {
          setStatus("Job status unavailable.", "error");
          startBtn.disabled = false;
          return;
        }
        if (data.status === "error") {
          setStatus(`Analysis failed: ${data.message || "unknown error"}`, "error");
          startBtn.disabled = false;
          return;
        }
        if (data.status !== "done") {
          const progress = data.progress || 0;
          setStatus(`Running... ${progress}% ${data.message || ""}`, "info");
          pollTimer = setTimeout(() => pollJob(jobId), 1000);
          return;
        }
        setStatus("Analysis completed.", "ok");
        startBtn.disabled = false;
        if (data.result_refs) {
          renderAll(jobId, data.result_refs);
        }
      })
      .catch(() => {
        setStatus("Job status unavailable.", "error");
        startBtn.disabled = false;
      });
  }

  function renderAll(jobId, refs) {
    fetchGraph(jobId, refs.graph_url);
    fetchTimeline(jobId, refs.timeline_url);
    initSessions(jobId, refs.sessions_url);
  }

  function fetchGraph(jobId, url) {
    const requestUrl = url || `${API_GRAPH}?job_id=${encodeURIComponent(jobId)}`;
    fetch(requestUrl)
      .then((resp) => resp.json())
      .then((data) => {
        if (!data) return;
        renderGraphs(data);
      })
      .catch(() => {});
  }

  function renderGraphs(payload) {
    graphGrid.innerHTML = "";
    const graphs = payload.graphs || [];
    if (graphs.length) {
      graphs.forEach((item) => {
        renderGraph(item.elements, item.host);
      });
      return;
    }
    if (payload.elements) {
      renderGraph(payload.elements, "All Hosts");
    }
  }

  function renderGraph(elements, hostLabel) {
    const panel = document.createElement("div");
    panel.className = "lt-graph-panel";
    const label = document.createElement("div");
    label.className = "lt-graph-label";
    label.textContent = hostLabel || "Host";
    const canvas = document.createElement("div");
    canvas.className = "lt-graph-canvas";
    panel.appendChild(label);
    panel.appendChild(canvas);
    graphGrid.appendChild(panel);

    const cy = cytoscape({
      container: canvas,
      elements: elements,
      layout: { name: "cose", animate: false },
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#2563eb",
            label: "data(label)",
            color: "#0f172a",
            "font-size": "10px",
            "text-valign": "center",
            "text-halign": "center",
            width: "mapData(weight, 1, 20, 20, 48)",
            height: "mapData(weight, 1, 20, 20, 48)",
          },
        },
        {
          selector: 'node[type="user"]',
          style: { "background-color": "#16a34a" },
        },
        {
          selector: 'node[type="ip"]',
          style: { "background-color": "#f59e0b" },
        },
        {
          selector: 'node[type="host"]',
          style: { "background-color": "#2563eb" },
        },
        {
          selector: "edge",
          style: {
            "line-color": "#94a3b8",
            "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle",
            width: "mapData(success_count, 1, 20, 1, 4)",
            "curve-style": "bezier",
          },
        },
      ],
    });
    cyInstances.push(cy);
  }

  function fetchTimeline(jobId, url) {
    const requestUrl = url || `${API_TIMELINE}?job_id=${encodeURIComponent(jobId)}`;
    fetch(requestUrl)
      .then((resp) => resp.json())
      .then((data) => {
        if (!data || !data.series) return;
        renderTimeline(data);
      })
      .catch(() => {});
  }

  function renderTimeline(payload) {
    const success = (payload.series.success || []).map((item) => ({ x: item.t, y: item.v }));
    const fail = (payload.series.fail || []).map((item) => ({ x: item.t, y: item.v }));
    const unit = payload.bucket === "day" ? "day" : "hour";
    const ctx = timelineCanvas.getContext("2d");
    timelineChart = new Chart(ctx, {
      type: "line",
      data: {
        datasets: [
          {
            label: "Success",
            data: success,
            borderColor: "#16a34a",
            backgroundColor: "rgba(22, 163, 74, 0.2)",
            tension: 0.25,
          },
          {
            label: "Fail",
            data: fail,
            borderColor: "#dc2626",
            backgroundColor: "rgba(220, 38, 38, 0.2)",
            tension: 0.25,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            type: "time",
            time: { unit: unit },
          },
          y: { beginAtZero: true },
        },
        plugins: {
          legend: { position: "bottom" },
        },
      },
    });
  }

  function initSessions(jobId, url) {
    const table = $("#lt-sessions-table");
    sessionsTable = table.DataTable({
      serverSide: true,
      processing: true,
      paging: true,
      ajax: function (data, callback) {
        const baseUrl = url || API_SESSIONS;
        const requestUrl = new URL(baseUrl, window.location.origin);
        requestUrl.searchParams.set("job_id", jobId);
        requestUrl.searchParams.set("draw", data.draw);
        requestUrl.searchParams.set("start", data.start);
        requestUrl.searchParams.set("length", data.length);
        if (data.search && data.search.value) {
          requestUrl.searchParams.set("search[value]", data.search.value);
        }
        fetch(requestUrl.toString())
          .then((resp) => resp.json())
          .then((json) => callback(json))
          .catch(() => callback({ draw: data.draw, recordsTotal: 0, recordsFiltered: 0, data: [] }));
      },
      columns: [
        { data: "host_ip" },
        { data: "session_id" },
        { data: "user" },
        { data: "src_ip" },
        { data: "start_time" },
        { data: "end_time" },
        { data: "events" },
        { data: "status" },
        {
          data: null,
          orderable: false,
          render: function () {
            return '<button class="lt-table-btn lt-detail-btn" type="button">Details</button>';
          },
        },
      ],
    });

    table.on("click", ".lt-detail-btn", function () {
      const tr = $(this).closest("tr");
      const row = sessionsTable.row(tr);
      if (row.child.isShown()) {
        row.child.hide();
        tr.removeClass("shown");
        return;
      }
      const data = row.data();
      if (!data) return;
      fetchSessionEvents(jobId, data)
        .then((events) => {
          row.child(renderSessionEvents(events)).show();
          tr.addClass("shown");
        })
        .catch(() => {
          row.child('<div class="lt-detail-wrap">Failed to load events.</div>').show();
          tr.addClass("shown");
        });
    });
  }

  function fetchSessionEvents(jobId, row) {
    const params = new URLSearchParams();
    params.set("job_id", jobId);
    params.set("host_ip", row.host_ip || "");
    params.set("session_id", row.session_id || "");
    if (row.start_time) params.set("start_time", row.start_time);
    if (row.end_time) params.set("end_time", row.end_time);
    const requestUrl = API_SESSION_EVENTS + "?" + params.toString();
    return fetch(requestUrl)
      .then((resp) => resp.json())
      .then((data) => data.events || []);
  }

  function renderSessionEvents(events) {
    if (!events || !events.length) {
      return '<div class="lt-detail-wrap">No events.</div>';
    }
    const rows = events
      .map((ev) => {
        const user = ev.entities && ev.entities.user ? ev.entities.user : "";
        const src = ev.entities && ev.entities.src_ip ? ev.entities.src_ip : "";
        return (
          "<tr>" +
          `<td>${ev.timestamp || ""}</td>` +
          `<td>${ev.event_type || ""}</td>` +
          `<td>${ev.raw_id || ""}</td>` +
          `<td>${user}</td>` +
          `<td>${src}</td>` +
          `<td>${ev.description || ""}</td>` +
          "</tr>"
        );
      })
      .join("");
    return (
      '<div class="lt-detail-wrap">' +
      '<table class="lt-detail-table">' +
      "<thead><tr><th>Time</th><th>Type</th><th>ID</th><th>User</th><th>Source IP</th><th>Description</th></tr></thead>" +
      `<tbody>${rows}</tbody>` +
      "</table></div>"
    );
  }

  initHostMultiSelect();
  startBtn.addEventListener("click", startAnalysis);
})();
