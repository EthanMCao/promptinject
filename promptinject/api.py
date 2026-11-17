"""Local firewall and replay API. Text inspection only; no network/tool execution."""

import threading
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from promptinject import ROOT
from promptinject.engine import load_cases, run
from promptinject.models import RunConfig, ScanRequest
from promptinject.scanner import scan
from promptinject.store import Store


def create_app(db_path=None):
    app = FastAPI(
        title="PromptInject Lab", version="1.0.0", docs_url=None, redoc_url=None
    )
    store = Store(db_path or ROOT / "data/runs.sqlite3")
    gate = threading.Lock()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0]
        if host not in {"localhost", "127.0.0.1", "testserver"}:
            return JSONResponse({"detail": "Host not allowed"}, status_code=400)
        if request.method not in {"GET", "HEAD"}:
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse(
                    {"detail": "Cross-origin writes denied"}, status_code=403
                )
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/docs", include_in_schema=False)
    def docs():
        return FileResponse(ROOT / "promptinject/static/docs.html")

    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": "firewall-replay"}

    @app.post("/api/scan")
    def inspect_text(request: ScanRequest):
        if not gate.acquire(blocking=False):
            raise HTTPException(409, "An inspection or evaluation is already running")
        try:
            return scan(request)
        finally:
            gate.release()

    @app.get("/api/cases")
    def cases():
        return [c.model_dump() for c in load_cases(ROOT / "corpus/cases.json")]

    @app.get("/api/runs")
    def runs():
        return store.list()

    @app.get("/api/runs/{id}")
    def get_run(id: str):
        report = store.get(id)
        if report is None:
            raise HTTPException(404, "Run not found")
        return report

    @app.post("/api/runs", status_code=201)
    def start_run(config: RunConfig):
        if not gate.acquire(blocking=False):
            raise HTTPException(409, "An evaluation is already running")
        try:
            return store.save(run(load_cases(ROOT / "corpus/cases.json"), config))
        finally:
            gate.release()

    @app.get("/source")
    def source():
        path = ROOT / "dist/source.tar.gz"
        if not path.exists():
            raise HTTPException(
                503,
                "Run python3 scripts/package_source.py to generate corresponding source",
            )
        return FileResponse(
            path, filename="promptinject-source.tar.gz", media_type="application/gzip"
        )

    app.mount(
        "/static", StaticFiles(directory=ROOT / "promptinject/static"), name="static"
    )

    @app.get("/")
    def index():
        return FileResponse(ROOT / "promptinject/static/index.html")

    return app
