// DOM unit tests only: no real browser, network, or visual layout assertions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Window } from "happy-dom";

const base = JSON.parse(readFileSync("benchmarks/baseline.json", "utf8"));
const html = readFileSync("promptinject/static/index.html", "utf8");
const script = readFileSync("promptinject/static/app.js", "utf8");
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function until(predicate) {
  for (let n = 0; n < 50; n++) {
    if (predicate()) return;
    await tick();
  }
  assert.fail("DOM update did not finish");
}

async function setup(
  t,
  { empty = false, error = false, payload = false } = {},
) {
  const window = new Window({
    url: "http://testserver/",
    settings: {
      enableJavaScriptEvaluation: true,
      disableJavaScriptFileLoading: true,
      suppressInsecureJavaScriptEnvironmentWarning: true,
    },
  });
  t.after(() => window.happyDOM.close());
  window.document.write(html);
  // Happy DOM omits the browser's Option constructor; use its real option element.
  window.Option = function (text, value) {
    const option = window.document.createElement("option");
    option.textContent = text;
    option.value = value;
    return option;
  };
  const report = {
    ...structuredClone(base),
    id: "run-test",
    created: "2026-11-16T20:00:00Z",
  };
  if (payload)
    report.cases[0].steps[0].text =
      '<img src=x onerror="window.compromised=true">';
  let history = empty ? [] : [report];
  const requests = [];
  window.fetch = async (path, options = {}) => {
    requests.push({ path, ...options });
    const respond = (body, status = 200) => ({
      ok: status < 400,
      status,
      json: async () => structuredClone(body),
      text: async () => JSON.stringify(body),
    });
    if (path === "/api/cases") return respond(report.cases);
    if (options.method === "POST") {
      if (error) return respond({ detail: "test failure" }, 503);
      history = [report, ...history];
      return respond(report, 201);
    }
    if (path === "/api/runs") return respond(history);
    if (path === "/api/runs/run-test") return respond(report);
    throw Error("Unexpected request: " + path);
  };
  window.eval(script);
  const $ = (id) => window.document.getElementById(id);
  try {
    await until(() =>
      $("status").textContent.includes(
        empty ? "No evaluations" : "Evaluation complete",
      ),
    );
  } catch (error) {
    throw new Error("Dashboard status: " + $("status").textContent, {
      cause: error,
    });
  }
  return { window, $, report, requests };
}

test("history renders actual metrics, policies, cases and export link", async (t) => {
  const { $, report } = await setup(t);
  assert.equal($("metrics").children.length, 4);
  assert.match($("metrics").textContent, /54.2%/);
  assert.equal($("policies").children.length, 4);
  assert.equal($("cases").children.length, 40);
  assert.match($("download").href, /\/api\/runs\/run-test$/);
  assert.ok($("provenance").textContent.includes(report.decision_sha256));
});

test("missed attacks, false positives, search, and policy filters", async (t) => {
  const { window, $ } = await setup(t);
  const change = (id, value) => {
    $(id).value = value;
    $(id).dispatchEvent(new window.Event("input"));
  };
  change("outcome", "miss");
  assert.equal($("cases").children.length, 11);
  change("outcome", "false_positive");
  assert.equal($("cases").children.length, 2);
  change("outcome", "all");
  change("policy", "disabled");
  change("outcome", "miss");
  assert.equal($("cases").children.length, 24);
  change("search", "no-match-for-this-query");
  assert.match($("cases").textContent, /No cases match/);
});

test("new evaluation sends selected split and variants then unlocks button", async (t) => {
  const { $, requests } = await setup(t, { empty: true });
  $("split").value = "holdout";
  $("variants").value = "all";
  $("run").click();
  await until(
    () =>
      !$("run").disabled &&
      $("status").textContent.includes("Evaluation complete"),
  );
  const request = requests.find((r) => r.method === "POST");
  const config = JSON.parse(request.body);
  assert.equal(config.split, "holdout");
  assert.deepEqual(config.policies, ["custom", "upstream"]);
  assert.equal(config.variants.length, 4);
});

test("API error is visible and run button recovers", async (t) => {
  const { $ } = await setup(t, { error: true });
  $("run").click();
  await until(
    () => !$("run").disabled && $("status").textContent.includes("503"),
  );
  assert.match($("status").textContent, /test failure/);
});

test("trace inspector shows source payload as text, not executable HTML", async (t) => {
  const { window, $, report } = await setup(t, { payload: true });
  const target = report.cases[0].id;
  $("search").value = target;
  $("search").dispatchEvent(new window.Event("input"));
  $("cases").querySelector("button").click();
  assert.equal($("trace").open, true);
  assert.match($("trace-body").textContent, /<img src=x/);
  assert.equal($("trace-body").querySelector("img"), null);
  assert.equal(window.compromised, undefined);
  $("close").click();
  assert.equal($("trace").open, false);
});

test("offline API reference renders schema with text-safe endpoint names", async (t) => {
  const window = new Window({
    url: "http://testserver/docs",
    settings: {
      enableJavaScriptEvaluation: true,
      disableJavaScriptFileLoading: true,
      suppressInsecureJavaScriptEnvironmentWarning: true,
    },
  });
  t.after(() => window.happyDOM.close());
  window.document.write(readFileSync("promptinject/static/docs.html", "utf8"));
  window.fetch = async () => ({
    ok: true,
    json: async () => ({
      info: { title: "Lab", version: "1" },
      paths: {
        "/api/runs": {
          post: {
            summary: "Run <script>example</script>",
            responses: { 201: { description: "Created" } },
          },
        },
      },
      components: { schemas: { RunConfig: { type: "object" } } },
    }),
  });
  window.eval(readFileSync("promptinject/static/docs.js", "utf8"));
  await until(() =>
    window.document
      .getElementById("docs-status")
      .textContent.includes("1 documented paths"),
  );
  assert.match(
    window.document.getElementById("endpoints").textContent,
    /POST \/api\/runs/,
  );
  assert.equal(
    window.document.getElementById("endpoints").querySelector("script"),
    null,
  );
});
