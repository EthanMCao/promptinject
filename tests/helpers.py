"""Construct changed, internally consistent reports for regression-gate tests."""

from promptinject.engine import digest
from promptinject.metrics import summarize


def refresh(report):
    for row in report["results"]:
        row["trajectory"][-1]["decision"] = "block" if row["blocked"] else "allow"
    report["summaries"] = {
        p: summarize([r for r in report["results"] if r["policy"] == p])
        for p in report["config"]["policies"]
    }
    report["decision_sha256"] = digest(
        [
            {k: r[k] for k in ("case_id", "variant", "policy", "blocked")}
            for r in report["results"]
        ]
    )
    return report
