"""Check scheduling determinism and the largest built-in replay configuration.

Writes temporary evidence under artifacts/verification; does not replace baselines.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify():
    output = ROOT / "artifacts/verification"
    output.mkdir(parents=True, exist_ok=True)
    digests = []
    for seed in ("0", "1", "42"):
        path = output / f"hash-seed-{seed}.json"
        environment = {**os.environ, "PYTHONHASHSEED": seed}
        subprocess.run(
            [
                sys.executable,
                "-m",
                "promptinject",
                "benchmark",
                "--repeats",
                "1",
                "--output",
                str(path),
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
        )
        report = json.loads(path.read_text())
        digests.append(report["decision_sha256"])
        subprocess.run(
            [
                sys.executable,
                "-m",
                "promptinject",
                "compare",
                "benchmarks/baseline.json",
                str(path),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
    assert len(set(digests)) == 1, "Decisions vary with Python hash randomization"
    path = output / "max-workload.json"
    reference = output / "max-workload-reference.json"
    for repeats, target in [(1, reference), (20, path)]:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "promptinject",
                "benchmark",
                "--repeats",
                str(repeats),
                "--policies",
                "custom",
                "upstream",
                "ingress_only",
                "relaxed",
                "disabled",
                "--variants",
                "original",
                "base64",
                "zero_width",
                "quoted",
                "--output",
                str(target),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
    subprocess.run(
        [sys.executable, "-m", "promptinject", "compare", str(reference), str(path)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    report = json.loads(path.read_text())
    result = {
        "python_hash_seeds": [0, 1, 42],
        "decision_sha256": digests[0],
        "max_workload_trials": len(report["results"]),
        "max_workload_measured_replays": sum(
            len(row["latencies_ms"]) for row in report["results"]
        ),
        "regression_passed": True,
    }
    (output / "benchmark-checks.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    verify()
