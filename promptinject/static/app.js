"use strict";
const $ = (id) => document.getElementById(id);
let active = null;
let corpus = [];
const pct = (n) => (n == null ? "N/A" : `${(100 * n).toFixed(1)}%`);
const el = (tag, text, cls) => {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
};
async function api(path, options) {
  const r = await fetch(path, options);
  if (!r.ok)
    throw new Error(
      `Request failed (${r.status}): ${(await r.text()).slice(0, 180)}`,
    );
  return r.json();
}
function bar(value) {
  const b = el("div", undefined, "bar"),
    i = el("i");
  i.style.width = `${100 * (value || 0)}%`;
  b.append(i);
  return b;
}
function render() {
  const s =
    active.summaries.custom ||
    active.summaries.upstream ||
    Object.values(active.summaries)[0];
  $("metrics").replaceChildren();
  for (const [title, value, note] of [
    [
      "DETECTION RECALL",
      pct(s.recall),
      `${s.tp} blocked / ${s.tp + s.fn} attacks`,
    ],
    [
      "FALSE POSITIVE RATE",
      pct(s.false_positive_rate),
      `${s.fp} flagged / ${s.fp + s.tn} benign`,
    ],
    ["REPLAY CASES", s.total, "Unique cases × selected variants"],
    [
      "p95 INSPECTION",
      `${s.p95_ms.toFixed(2)} ms`,
      "Local firewall only · excludes model latency",
    ],
  ]) {
    const m = el("article", undefined, "metric");
    m.append(
      el("div", title, "eyebrow"),
      el("strong", value),
      el("small", note),
    );
    $("metrics").append(m);
  }
  $("policies").replaceChildren();
  $("policy").replaceChildren();
  for (const [p, x] of Object.entries(active.summaries)) {
    $("policy").append(new Option(p, p));
    const tr = el("tr");
    tr.append(el("td", p));
    const recall = el("td", pct(x.recall));
    recall.append(bar(x.recall));
    tr.append(
      recall,
      ...[
        pct(x.false_positive_rate),
        pct(x.precision),
        x.f1?.toFixed(3) || "N/A",
        `${x.p95_ms.toFixed(2)} ms`,
      ].map((v) => el("td", v)),
    );
    $("policies").append(tr);
  }
  $("categories").replaceChildren();
  for (const [name, x] of Object.entries(s.by_category)) {
    if (x.recall == null) continue;
    const row = el("div", undefined, "category"),
      right = el("div");
    right.append(el("small", `${x.tp}/${x.tp + x.fn}`), bar(x.recall));
    row.append(el("span", name.replaceAll("_", " ")), right);
    $("categories").append(row);
  }
  $("provenance").replaceChildren();
  for (const [k, v] of [
    ["Mode", active.mode],
    ["Corpus SHA-256", active.corpus_sha256],
    ["Decision SHA-256", active.decision_sha256],
    ["Upstream commit", active.upstream_commit],
    ["Runtime", `Python ${active.python} · seed ${active.config.seed}`],
    [
      "Recall 95% Wilson interval",
      s.recall_ci95?.map(pct).join(" – ") || "N/A",
    ],
  ])
    $("provenance").append(el("dt", k), el("dd", v));
  $("download").href = `/api/runs/${active.id}`;
  $("status").textContent =
    `Evaluation complete · ${new Date(active.created).toLocaleString()} · ${active.config.split} split · ${s.consistent ? "Repeated decisions consistent" : "Decision inconsistency detected"}`;
  renderCases();
}
function renderCases() {
  if (!active) return;
  const query = $("search").value.toLowerCase(),
    outcome = $("outcome").value;
  const rows = active.results.filter(
    (r) =>
      r.policy === $("policy").value &&
      `${r.case_id} ${r.category}`.toLowerCase().includes(query) &&
      (outcome === "all" ||
        (outcome === "miss" && r.malicious && !r.blocked) ||
        (outcome === "false_positive" && !r.malicious && r.blocked) ||
        (outcome === "blocked" && r.blocked)),
  );
  $("cases").replaceChildren();
  for (const r of rows) {
    const tr = el("tr"),
      decision = el("td"),
      trace = el("td"),
      button = el("button", "Inspect ↗", "trace-btn");
    decision.append(
      el(
        "span",
        r.blocked ? "BLOCK" : "ALLOW",
        `badge ${r.blocked !== r.malicious ? "bad" : r.blocked ? "" : "warn"}`,
      ),
    );
    button.addEventListener("click", () => {
      $("trace-title").textContent = r.case_id;
      $("trace-body").textContent = JSON.stringify(
        {
          case: (active.cases || corpus).find((c) => c.id === r.case_id),
          replay: r,
        },
        null,
        2,
      );
      $("trace").showModal();
    });
    trace.append(button);
    tr.append(
      el("td", r.case_id),
      el("td", `${r.category} / ${r.stage}`),
      el("td", r.variant),
      el("td", r.malicious ? "Attack" : "Benign"),
      decision,
      trace,
    );
    $("cases").append(tr);
  }
  if (!rows.length) {
    const tr = el("tr"),
      td = el("td", "No cases match these filters.");
    td.colSpan = 6;
    tr.append(td);
    $("cases").append(tr);
  }
}
async function history(id) {
  const runs = await api("/api/runs");
  $("history").replaceChildren(
    ...runs.map(
      (r) =>
        new Option(
          `${new Date(r.created).toLocaleString()} · ${r.config.split}`,
          r.id,
        ),
    ),
  );
  if (runs.length) {
    $("history").value = id || runs[0].id;
    active = await api(`/api/runs/${$("history").value}`);
    render();
  } else
    $("status").textContent =
      "No evaluations yet. Run the authored corpus to create your first baseline.";
}
$("run").addEventListener("click", async () => {
  const b = $("run");
  b.disabled = true;
  $("status").textContent =
    "Comparing the custom firewall with the upstream baseline…";
  try {
    const report = await api("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        split: $("split").value,
        policies: ["custom", "upstream"],
        variants:
          $("variants").value === "all"
            ? ["original", "base64", "zero_width", "quoted"]
            : ["original"],
      }),
    });
    await history(report.id);
  } catch (e) {
    $("status").textContent = e.message;
  } finally {
    b.disabled = false;
  }
});
$("history").addEventListener("change", async () => {
  try {
    active = await api(`/api/runs/${$("history").value}`);
    render();
  } catch (e) {
    $("status").textContent = e.message;
  }
});
for (const id of ["policy", "outcome", "search"])
  $(id).addEventListener("input", renderCases);
$("close").addEventListener("click", () => $("trace").close());
(async () => {
  try {
    corpus = await api("/api/cases");
    await history();
  } catch (e) {
    $("status").textContent = e.message;
  }
})();
