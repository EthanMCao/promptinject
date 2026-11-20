"""Package corresponding source, excluding runtime data and secrets."""

import gzip
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = [
    "promptinject",
    "tests",
    "scripts",
    "corpus",
    "docs",
    "vendor",
    ".github",
    "README.md",
    "LICENSE",
    "NOTICE.md",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-upstream-tests.txt",
    "package.json",
    "package-lock.json",
    "Dockerfile",
    "compose.yaml",
    ".dockerignore",
    ".gitignore",
    "Makefile",
    "benchmarks/custom-firewall.json",
    "benchmarks/custom-firewall.csv",
    "benchmarks/baseline.json",
    "benchmarks/baseline.csv",
    "benchmarks/mutations.json",
    "benchmarks/mutations.csv",
    "benchmarks/holdout.json",
    "benchmarks/holdout.csv",
    "benchmarks/RESULTS.md",
]


def package():
    paths = []
    for name in INCLUDE:
        path = ROOT / name
        paths.extend(path.rglob("*") if path.is_dir() else [path])
    target = ROOT / "dist/source.tar.gz"
    target.parent.mkdir(exist_ok=True)
    with (
        target.open("wb") as output,
        gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w|") as archive,
    ):
        for path in sorted(paths):
            if (
                not path.is_file()
                or path.is_symlink()
                or any(
                    part in {"__pycache__", ".pytest_cache", ".ruff_cache", ".hypothesis"}
                    for part in path.parts
                )
                or any(part.startswith(".env") for part in path.parts)
                or path.suffix
                not in {
                    ".py",
                    ".md",
                    ".json",
                    ".csv",
                    ".yaml",
                    ".yml",
                    ".toml",
                    ".lock",
                    ".txt",
                    ".js",
                    ".mjs",
                    ".css",
                    ".html",
                    "",
                }
            ):
                continue
            info = archive.gettarinfo(
                str(path), arcname="promptinject/" + path.relative_to(ROOT).as_posix()
            )
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            with path.open("rb") as source:
                archive.addfile(info, source)
    print(target)


if __name__ == "__main__":
    package()
