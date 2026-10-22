"""Reject incomplete or edited benchmark reports before trusting their summaries."""

import math
from promptinject.models import Case, RunConfig
from promptinject.metrics import summarize


def validate_report(report):
    # Imported here to avoid a cycle: engine -> metrics -> report validation.
    from promptinject.engine import digest

    try:
        if report["schema_version"] != 1 or report["mode"] != "firewall-replay":
            raise ValueError("unsupported report format")
        config = RunConfig.model_validate(report["config"])
        cases = [Case.model_validate(c) for c in report["cases"]]
        if not cases or len({c.id for c in cases}) != len(cases):
            raise ValueError("empty or duplicate source cases")
        if digest([c.model_dump() for c in cases]) != report["corpus_sha256"]:
            raise ValueError("corpus hash mismatch")
        if set(report["policy_configs"]) != set(config.policies):
            raise ValueError("policy configuration mismatch")
        expected = {
            (p, c.id, v)
            for p in config.policies
            for c in cases
            for v in config.variants
            if v == "original"
            or (
                c.stage == "ingress"
                and any(s.role == "data" and s.text for s in c.steps)
            )
            or (c.stage == "egress" and c.response)
        }
        sources = {c.id: c for c in cases}
        seen = set()
        for row in report["results"]:
            key = (row["policy"], row["case_id"], row["variant"])
            if key not in expected or key in seen:
                raise ValueError("unexpected or duplicate trial")
            seen.add(key)
            case = sources[row["case_id"]]
            for field in ("malicious", "category", "stage", "split"):
                if row[field] != getattr(case, field):
                    raise ValueError("trial label mismatch")
            if type(row["blocked"]) is not bool or type(row["consistent"]) is not bool:
                raise ValueError("trial decisions must be booleans")
            if len(row["latencies_ms"]) != config.repeats or any(
                isinstance(t, bool)
                or not isinstance(t, (int, float))
                or not math.isfinite(t)
                or t < 0
                for t in row["latencies_ms"]
            ):
                raise ValueError("invalid latency samples")
            if not row["trajectory"] or row["trajectory"][-1]["decision"] != (
                "block" if row["blocked"] else "allow"
            ):
                raise ValueError("trajectory contradicts decision")
        if seen != expected:
            raise ValueError("missing trials")
        derived = {
            p: summarize([r for r in report["results"] if r["policy"] == p])
            for p in config.policies
        }
        if derived != report["summaries"]:
            raise ValueError("summaries do not match trial evidence")
        decisions = [
            {k: r[k] for k in ("case_id", "variant", "policy", "blocked")}
            for r in report["results"]
        ]
        if digest(decisions) != report["decision_sha256"]:
            raise ValueError("decision hash mismatch")
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise ValueError(f"invalid report: {error}") from error
