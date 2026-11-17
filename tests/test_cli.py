import json
import sys
import tarfile
from tests.helpers import refresh
from promptinject.__main__ import main
from promptinject import ROOT


def invoke(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["promptinject", *map(str, args)])
    return main()


def test_cli_exports_and_gates(tmp_path, monkeypatch):
    out = tmp_path / "run.json"
    assert invoke(monkeypatch, "benchmark", "--output", out, "--repeats", "1") == 0
    assert out.with_suffix(".csv").read_text().startswith("policy,case_id")
    assert invoke(monkeypatch, "compare", out, out) == 0
    bad = json.loads(out.read_text())
    for row in bad["results"]:
        if row["malicious"]:
            row["blocked"] = False
    refresh(bad)
    other = tmp_path / "bad.json"
    other.write_text(json.dumps(bad))
    assert invoke(monkeypatch, "compare", out, other) == 1
    assert invoke(monkeypatch, "compare", out, other, "--max-recall-drop", "-1") == 2
    assert invoke(monkeypatch, "benchmark", "--corpus", tmp_path / "missing.json") == 2


def test_corpus_generator_reproduces_checked_in_corpus():
    import subprocess

    path = ROOT / "corpus/cases.json"
    before = path.read_bytes()
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_corpus.py")],
        check=True,
        capture_output=True,
    )
    assert path.read_bytes() == before


def test_source_archive_is_reproducible_and_contains_license():
    from scripts.package_source import package

    package()
    path = ROOT / "dist/source.tar.gz"
    before = path.read_bytes()
    package()
    assert path.read_bytes() == before
    with tarfile.open(path) as archive:
        names = archive.getnames()
        assert "promptinject/LICENSE" in names
        assert "promptinject/vendor/upstream/LICENSE" in names
        assert "promptinject/promptinject/engine.py" in names
        for dependency_file in (
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-upstream-tests.txt",
        ):
            member = archive.extractfile(f"promptinject/{dependency_file}")
            assert member is not None
            assert member.read() == (ROOT / dependency_file).read_bytes()
        assert not any(
            "/data/" in p or "/.env" in p or "__pycache__" in p for p in names
        )


def test_inspect_single_case(monkeypatch, capsys):
    assert invoke(monkeypatch, "inspect", "instruction_override-0") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["case"]["id"] == "instruction_override-0"
    assert result["result"]["blocked"] is True
    assert invoke(monkeypatch, "inspect", "unknown-case") == 2


def test_source_archive_excludes_environment_files_and_symlinks():
    from scripts.package_source import package

    secret = ROOT / "docs/.env.test-fixture"
    link = ROOT / "docs/source-test-link.md"
    try:
        secret.write_text("TEST_FIXTURE_NOT_A_SECRET=1")
        link.symlink_to(ROOT / "README.md")
        package()
        with tarfile.open(ROOT / "dist/source.tar.gz") as archive:
            names = archive.getnames()
            assert not any(
                ".env.test-fixture" in name or "source-test-link" in name
                for name in names
            )
    finally:
        secret.unlink(missing_ok=True)
        link.unlink(missing_ok=True)
