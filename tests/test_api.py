import concurrent.futures
import pytest
from fastapi.testclient import TestClient
from promptinject.api import create_app
from promptinject.store import Store


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "runs.db")) as client:
        yield client


def test_run_persistence_and_dashboard(client):
    assert client.get("/").status_code == 200
    assert "Content-Security-Policy" in client.get("/").headers
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/api/health").json()["status"] == "ok"
    assert len(client.get("/api/cases").json()) == 40
    r = client.post("/api/runs", json={"repeats": 1})
    assert r.status_code == 201
    data = r.json()
    assert client.get("/api/runs/" + data["id"]).json() == data
    assert client.get("/api/runs").json()[0]["id"] == data["id"]
    assert "results" not in client.get("/api/runs").json()[0]
    assert client.get("/api/runs/missing").status_code == 404


def test_invalid_config_and_cross_origin(client):
    assert client.post("/api/runs", json={"repeats": 100000}).status_code == 422
    assert (
        client.post(
            "/api/runs", json={}, headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert (
        client.get("/api/health", headers={"Host": "evil.example"}).status_code == 400
    )
    assert client.get("/static/../../LICENSE").status_code == 404


def test_store_concurrent_writers_and_injection(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda n: store.save({"number": n}), range(12)))
    assert len(store.list()) == 12
    assert store.get("' OR 1=1 --") is None
    assert len({r["id"] for r in rows}) == 12


def test_source_archive(client):
    r = client.get("/source")
    assert r.status_code in {200, 503}
    if r.status_code == 200:
        assert r.headers["content-type"] == "application/gzip"


def test_concurrent_evaluation_rejected(client, monkeypatch):
    import threading
    import promptinject.api as module

    entered, release = threading.Event(), threading.Event()
    original = module.run

    def slow(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(module, "run", slow)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        first = pool.submit(client.post, "/api/runs", json={"repeats": 1})
        try:
            assert entered.wait(5)
            assert client.post("/api/runs", json={}).status_code == 409
        finally:
            release.set()
        assert first.result().status_code == 201


def test_evaluation_lock_released_after_error(client, monkeypatch):
    import promptinject.api as module

    original = module.run

    def fail(*args):
        raise RuntimeError("test failure")

    monkeypatch.setattr(module, "run", fail)
    with pytest.raises(RuntimeError):
        client.post("/api/runs", json={})
    monkeypatch.setattr(module, "run", original)
    assert client.post("/api/runs", json={"repeats": 1}).status_code == 201


def test_source_cases_preserved_in_report(client):
    result = client.post(
        "/api/runs", json={"repeats": 1, "policies": ["upstream"]}
    ).json()
    assert len(result["cases"]) == 40
    first = result["results"][0]
    assert first["case_id"] in {c["id"] for c in result["cases"]}
    assert "cases" not in client.get("/api/runs").json()[0]


def test_docs_work_under_csp_without_cdn(client):
    from html.parser import HTMLParser

    class Assets(HTMLParser):
        urls = []

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "script":
                assert attrs.get("src", "").startswith("/static/")
                self.urls.append(attrs["src"])
            if tag == "link" and attrs.get("rel") == "stylesheet":
                self.urls.append(attrs["href"])

    page = client.get("/docs")
    assert page.status_code == 200
    assert "cdn.jsdelivr.net" not in page.text
    assets = Assets()
    assets.feed(page.text)
    assert len(assets.urls) == 2
    for url in assets.urls:
        assert client.get(url).status_code == 200
    assert "/api/runs" in client.get("/openapi.json").json()["paths"]


def test_same_origin_post_allowed_and_database_survives_restart(tmp_path):
    path = tmp_path / "persistent.sqlite3"
    with TestClient(create_app(path)) as first:
        result = first.post(
            "/api/runs",
            headers={"Origin": "http://testserver"},
            json={"repeats": 1, "policies": ["disabled"]},
        )
        assert result.status_code == 201
        id = result.json()["id"]
    with TestClient(create_app(path)) as second:
        assert second.get("/api/runs/" + id).status_code == 200


def test_database_rollback_and_connection_close(tmp_path):
    import sqlite3

    store = Store(tmp_path / "db.sqlite3")
    with pytest.raises(RuntimeError):
        with store.connect() as conn:
            conn.execute("INSERT INTO runs VALUES ('broken','today','{}')")
            raise RuntimeError("simulate failed transaction")
    assert store.get("broken") is None
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")
