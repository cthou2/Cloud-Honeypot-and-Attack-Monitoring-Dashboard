const API_BASE = "";

const REFRESH_SECONDS = 30;
const EVENTS_TO_LOAD = 500;
const ROWS_PER_PAGE = 25;


let allEvents = [];
let filteredEvents = [];
let currentPage = 0;
let refreshTimer = null;


let timelineChart = null;
let sourcesChart = null;
let usernamesChart = null;

async function getJSON(path) {
  const response = await fetch(API_BASE + path);
  if (!response.ok) {
    throw new Error(path + " returned " + response.status);
  }
  return response.json();
}

function $(id) {
  return document.getElementById(id);
}

function formatTime(value) {
  if (!value) return "–";
  return new Date(value).toLocaleString();
}

function getRisk(event) {
  const type = event.event_type || "";
  if (type === "cowrie.command.input" || type.includes("file_download")) {
    return "high";
  }
  if (type === "cowrie.login.success") {
    return "medium";
  }
  return "low";
}

function makeCell(text, className) {
  const td = document.createElement("td");
  td.textContent = text ?? "–";
  if (className) td.className = className;
  return td;
}


async function loadHealth() {
  const status = $("status");
  try {
    const health = await getJSON("/api/health");
    status.textContent = "API " + health.api + " · DB " + health.database;
    status.className = "status online";
  } catch (error) {
    status.textContent = "API offline";
    status.className = "status offline";
  }
}

async function loadStatistics() {
  const stats = await getJSON("/api/statistics");
  $("totalEvents").textContent = stats.total_events;
  $("uniqueSources").textContent = stats.unique_sources;
  $("failedLogins").textContent = stats.failed_logins;
  $("successLogins").textContent = stats.successful_logins;
  $("commandCount").textContent = stats.commands;
}

async function loadSources() {
  const data = await getJSON("/api/sources?limit=10");
  const labels = data.sources.map(row => row.source_ip);
  const counts = data.sources.map(row => row.event_count);
  sourcesChart = drawBarChart(sourcesChart, "sourcesChart", labels, counts, "#4ea8de");
}

async function loadUsernames() {
  const data = await getJSON("/api/usernames?limit=10");
  const labels = data.usernames.map(row => row.username);
  const counts = data.usernames.map(row => row.attempt_count);
  usernamesChart = drawBarChart(usernamesChart, "usernamesChart", labels, counts, "#d29922");
}

async function loadCommands() {
  const data = await getJSON("/api/commands?limit=10");
  const list = $("commandsList");
  list.innerHTML = "";

  if (data.commands.length === 0) {
    list.innerHTML = '<li class="empty">No commands recorded yet</li>';
    return;
  }

  data.commands.forEach(row => {
    const li = document.createElement("li");
    const code = document.createElement("code");
    const count = document.createElement("span");
    code.textContent = row.command;
    count.textContent = row.command_count;
    count.className = "count";
    li.append(code, count);
    li.title = "Click to filter the table";
    li.onclick = () => applySearch(row.command);
    list.appendChild(li);
  });
}

async function loadEvents() {
  const data = await getJSON("/api/events?limit=" + EVENTS_TO_LOAD);
  allEvents = data.events;
  fillTypeFilter();
  applyFilters(false);
  drawTimeline();
}

function drawBarChart(chart, canvasId, labels, values, color) {
  if (chart) {
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.update();
    return chart;
  }

  return new Chart($(canvasId), {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{ data: values, backgroundColor: color, borderRadius: 4 }],
    },
    options: {
      indexAxis: "y",
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#8b98a5", precision: 0 }, grid: { color: "#2a3540" } },
        y: { ticks: { color: "#e6edf3" }, grid: { display: false } },
      },
      onClick: (event, bars) => {
        if (bars.length > 0) {
          applySearch(labels[bars[0].index]);
        }
      },
    },
  });
}

function drawTimeline() {
  const perHour = {};

  allEvents.forEach(event => {
    if (!event.timestamp) return;
    const date = new Date(event.timestamp);
    date.setMinutes(0, 0, 0);
    const key = date.getTime();
    perHour[key] = (perHour[key] || 0) + 1;
  });

  const hours = Object.keys(perHour).map(Number).sort((a, b) => a - b);
  const labels = hours.map(h =>
    new Date(h).toLocaleString([], { month: "short", day: "numeric", hour: "numeric" })
  );
  const values = hours.map(h => perHour[h]);

  if (timelineChart) {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = values;
    timelineChart.update();
    return;
  }

  timelineChart = new Chart($("timelineChart"), {
    type: "line",
    data: {
      labels: labels,
      datasets: [{
        data: values,
        borderColor: "#4ea8de",
        backgroundColor: "rgba(78, 168, 222, .15)",
        fill: true,
        tension: 0.3,
        pointRadius: 3,
      }],
    },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#8b98a5", maxTicksLimit: 12 }, grid: { display: false } },
        y: { ticks: { color: "#8b98a5", precision: 0 }, grid: { color: "#2a3540" }, beginAtZero: true },
      },
    },
  });
}

function fillTypeFilter() {
  const select = $("typeFilter");
  const chosen = select.value;
  const types = [...new Set(allEvents.map(e => e.event_type).filter(Boolean))].sort();

  select.innerHTML = '<option value="">All event types</option>';
  types.forEach(type => {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = type.replace("cowrie.", "");
    select.appendChild(option);
  });
  select.value = chosen;
}

function applySearch(text) {
  $("searchBox").value = text;
  applyFilters(true);
  $("searchBox").scrollIntoView({ behavior: "smooth", block: "center" });
}

function applyFilters(resetPage) {
  const search = $("searchBox").value.trim().toLowerCase();
  const type = $("typeFilter").value;
  const risk = $("riskFilter").value;

  filteredEvents = allEvents.filter(event => {
    if (type && event.event_type !== type) return false;
    if (risk && getRisk(event) !== risk) return false;
    if (search) {
      const text = [event.source_ip, event.username, event.command, event.event_type]
        .join(" ")
        .toLowerCase();
      if (!text.includes(search)) return false;
    }
    return true;
  });

  if (resetPage) currentPage = 0;
  renderTable();
}

function renderTable() {
  const body = $("eventsBody");
  body.innerHTML = "";

  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / ROWS_PER_PAGE));
  if (currentPage >= totalPages) currentPage = totalPages - 1;

  const start = currentPage * ROWS_PER_PAGE;
  const pageRows = filteredEvents.slice(start, start + ROWS_PER_PAGE);

  if (pageRows.length === 0) {
    const row = document.createElement("tr");
    const cell = makeCell("No events match these filters", "empty");
    cell.colSpan = 6;
    row.appendChild(cell);
    body.appendChild(row);
  }

  pageRows.forEach(event => {
    const row = document.createElement("tr");
    const risk = getRisk(event);

    const riskCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "badge " + risk;
    badge.textContent = risk;
    riskCell.appendChild(badge);

    row.append(
      makeCell(formatTime(event.timestamp)),
      riskCell,
      makeCell((event.event_type || "").replace("cowrie.", "")),
      makeCell(event.source_ip),
      makeCell(event.username),
      makeCell(event.command, "cmd"),
    );
    row.onclick = () => showDetail(event);
    body.appendChild(row);
  });

  $("pageInfo").textContent =
    "Page " + (currentPage + 1) + " of " + totalPages +
    " · " + filteredEvents.length + " events";
  $("prevPage").disabled = currentPage === 0;
  $("nextPage").disabled = currentPage >= totalPages - 1;
}

function showDetail(event) {
  const list = $("detailList");
  list.innerHTML = "";

  const fields = { risk_level: getRisk(event), ...event };
  Object.entries(fields).forEach(([key, value]) => {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = key;
    dd.textContent = key.includes("timestamp") || key === "created_at"
      ? formatTime(value)
      : (value ?? "–");
    list.append(dt, dd);
  });

  $("detailOverlay").classList.remove("hidden");
}

function hideDetail() {
  $("detailOverlay").classList.add("hidden");
}

async function refreshAll() {
  await loadHealth();
  const parts = [loadStatistics, loadSources, loadUsernames, loadCommands, loadEvents];
  for (const load of parts) {
    try {
      await load();
    } catch (error) {
      console.error(error);
    }
  }
}

function setAutoRefresh(on) {
  clearInterval(refreshTimer);
  if (on) {
    refreshTimer = setInterval(refreshAll, REFRESH_SECONDS * 1000);
  }
}

$("refreshBtn").onclick = refreshAll;
$("autoRefresh").onchange = e => setAutoRefresh(e.target.checked);
$("searchBox").oninput = () => applyFilters(true);
$("typeFilter").onchange = () => applyFilters(true);
$("riskFilter").onchange = () => applyFilters(true);
$("clearFilters").onclick = () => {
  $("searchBox").value = "";
  $("typeFilter").value = "";
  $("riskFilter").value = "";
  applyFilters(true);
};
$("prevPage").onclick = () => { currentPage--; renderTable(); };
$("nextPage").onclick = () => { currentPage++; renderTable(); };
$("closeDetail").onclick = hideDetail;
$("detailOverlay").onclick = e => { if (e.target.id === "detailOverlay") hideDetail(); };
document.addEventListener("keydown", e => { if (e.key === "Escape") hideDetail(); });

// Start
refreshAll();
setAutoRefresh(true);
