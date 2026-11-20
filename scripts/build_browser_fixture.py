"""Render the real frontend with recorded TestClient responses when sockets are unavailable.

This is a browser fixture test, not a substitute for a live HTTP end-to-end test.
"""

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from promptinject import ROOT
from promptinject.api import create_app


def build():
    output = ROOT / "artifacts/browser-fixture"
    output.mkdir(parents=True, exist_ok=True)
    with TestClient(create_app(output / "responses.sqlite3")) as client:
        reports = {}
        for split in ("all", "development", "holdout"):
            for mutated in (False, True):
                variants = (
                    ["original", "base64", "zero_width", "quoted"]
                    if mutated
                    else ["original"]
                )
                response = client.post(
                    "/api/runs",
                    json={
                        "split": split,
                        "variants": variants,
                        "policies": ["custom", "upstream"],
                    },
                )
                response.raise_for_status()
                reports[split + ":" + str(mutated).lower()] = response.json()
        cases = client.get("/api/cases").json()
        schema = client.get("/openapi.json").json()
    for name in ("app.js", "playground.js", "docs.js", "style.css"):
        shutil.copyfile(ROOT / "promptinject/static" / name, output / name)
    for name in ("index.html", "docs.html"):
        html = (ROOT / "promptinject/static" / name).read_text().replace("/static/", "")
        html = html.replace(
            "<script defer",
            '<script defer src="fixture-api.js"></script><script defer',
            1,
        )
        html = html.replace('href="/docs"', 'href="docs.html"').replace(
            'href="/"', 'href="index.html"'
        )
        (output / name).write_text(html)
    (output / "fixture-api.js").write_text(
        """// Test harness: response fixtures produced by FastAPI TestClient.
const fixtures = """
        + json.dumps({"reports": reports, "cases": cases, "schema": schema})
        + """;
let saved = [];
window.fetch = async (path, options = {}) => {
  const answer = (data, status = 200) => ({ok:status < 400,status,json:async()=>structuredClone(data),text:async()=>JSON.stringify(data)});
  if(path === '/api/scan') return answer({detail:'Live inspection is unavailable in this recorded-response fixture'},503);
  if(path === '/api/cases') return answer(fixtures.cases);
  if(path === '/openapi.json') return answer(fixtures.schema);
  if(path === '/api/runs' && options.method === 'POST') {
    if(location.hash === '#simulate-error') return answer({detail:'Simulated unavailable API'},503);
    const config=JSON.parse(options.body);
    const report=structuredClone(fixtures.reports[config.split+':'+(config.variants.length>1)]);
    saved.unshift(report); return answer(report,201);
  }
  if(path === '/api/runs') return answer(saved);
  if(path.startsWith('/api/runs/')) return answer(saved.find(r=>r.id===path.split('/').pop()));
  return answer({detail:'Unknown fixture route'},404);
};
document.addEventListener('DOMContentLoaded',()=>{
  const note=document.createElement('p');
  note.textContent='BROWSER TEST FIXTURE · recorded API responses · no live HTTP server';
  document.querySelector('main').prepend(note);
});
"""
    )
    print(output / "index.html")


if __name__ == "__main__":
    build()
