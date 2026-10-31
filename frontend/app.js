import { analyze, parseLog } from "./engine.js";

const $ = (id) => document.getElementById(id);
const apiInput = $("api");
const params = new URLSearchParams(location.search);
apiInput.value = params.get("api") || localStorage.getItem("ls_api") || "";
let model, charts = {}, lastResults = [];

const setMode = () => {
  const api = apiInput.value.trim();
  localStorage.setItem("ls_api", api);
  $("modeBadge").textContent = api ? "API: Lambda/FastAPI" : "in-browser model";
  $("modeBadge").classList.toggle("api", Boolean(api));
};
apiInput.addEventListener("change", setMode);
setMode();

model = await (await fetch("model.json")).json();
$("metrics").textContent = `ROC-AUC ${model.metrics.roc_auc}, precision ${model.metrics.precision}, recall ${model.metrics.recall} on ${model.metrics.test_size} held-out sessions`;

$("sample").onclick = async () => { $("log").value = await (await fetch("sample.log")).text(); run(); };
$("file").onchange = async (e) => { $("log").value = await e.target.files[0].text(); run(); };
$("run").onclick = run;
$("copy").onclick = () => {
  const cmds = lastResults.filter((r) => r.verdict === "block").map((r) => `sudo ufw deny from ${r.ip}`).join("\n");
  navigator.clipboard.writeText(cmds || "# nothing to block");
  $("copy").textContent = "Copied ✓";
  setTimeout(() => ($("copy").textContent = "Copy ufw block commands"), 1500);
};

async function run() {
  const text = $("log").value;
  if (!text.trim()) return;
  const api = apiInput.value.trim().replace(/\/$/, "");
  let report;
  try {
    if (api) {
      const r = await fetch(`${api}/analyze`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log: text, host: "dashboard" }),
      });
      if (!r.ok) throw new Error(`API ${r.status}`);
      report = await r.json();
      report.events = parseLog(text); // charts are drawn client-side
    } else {
      report = analyze(model, text);
    }
  } catch (err) {
    alert(`Analysis failed: ${err.message}. Falling back to the in-browser model.`);
    report = analyze(model, text);
  }
  render(report);
}

function render({ summary, results, events }) {
  lastResults = results;
  ["kpis", "charts", "tableCard"].forEach((id) => ($(id).hidden = false));
  $("k-events").textContent = summary.events;
  $("k-ips").textContent = summary.ips;
  $("k-block").textContent = summary.blocked;
  $("k-susp").textContent = summary.suspicious;
  $("k-fail").textContent = summary.failed_logins;

  $("rows").innerHTML = results.map((r) => `
    <tr class="${r.verdict}">
      <td><code>${r.ip}</code></td>
      <td><div class="bar"><i style="width:${(r.score * 100).toFixed(0)}%"></i></div>${(r.score * 100).toFixed(1)}%</td>
      <td><span class="pill ${r.verdict}">${r.verdict}</span></td>
      <td>${r.failed_count}</td><td>${r.success_count}</td><td>${r.unique_users}</td>
      <td>${r.invalid_user_count}</td><td>${r.root_attempts}</td><td>${(+r.attempts_per_min).toFixed(1)}</td>
      <td>${String(r.first_seen).replace("T", " ")}</td>
    </tr>`).join("");

  // hourly timeline
  const hours = {};
  for (const e of events) {
    const h = e.ts.toISOString().slice(0, 13);
    hours[h] ||= { failed: 0, ok: 0 };
    if (e.kind === "failed") hours[h].failed++;
    if (e.kind === "accepted") hours[h].ok++;
  }
  const labels = Object.keys(hours).sort();
  draw("timeline", "bar", {
    labels: labels.map((l) => l.slice(5).replace("T", " ") + ":00"),
    datasets: [
      { label: "failed", data: labels.map((l) => hours[l].failed), backgroundColor: "#f43f5e" },
      { label: "accepted", data: labels.map((l) => hours[l].ok), backgroundColor: "#22c55e" },
    ],
  }, { scales: { x: { stacked: true }, y: { stacked: true } } });

  const users = {};
  for (const e of events) if (e.kind === "failed") users[e.user] = (users[e.user] || 0) + 1;
  const top = Object.entries(users).sort((a, b) => b[1] - a[1]).slice(0, 10);
  draw("users", "bar", {
    labels: top.map((u) => u[0]),
    datasets: [{ label: "failed attempts", data: top.map((u) => u[1]), backgroundColor: "#6366f1" }],
  }, { indexAxis: "y", scales: { y: { ticks: { autoSkip: false } } } });
}

function draw(id, type, data, options = {}) {
  charts[id]?.destroy();
  charts[id] = new Chart($(id), {
    type, data,
    options: { responsive: true, plugins: { legend: { labels: { color: "#cbd5e1" } } },
      scales: { x: { ticks: { color: "#94a3b8" }, ...(options.scales?.x || {}) }, y: { ...(options.scales?.y || {}), ticks: { color: "#94a3b8", ...(options.scales?.y?.ticks || {}) } } },
      indexAxis: options.indexAxis || "x" },
  });
}
