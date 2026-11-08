import copy
import json
import pytest
from promptinject import ROOT
from promptinject.engine import load_cases, run
from promptinject.metrics import compare
from promptinject.models import RunConfig
from promptinject.reports import validate_report


@pytest.fixture(scope="module")
def report():
    return run(
        load_cases(ROOT / "corpus/cases.json"),
        RunConfig(repeats=1, policies=["upstream"]),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(results=[]),
        lambda r: r["results"].append(r["results"][0]),
        lambda r: r["summaries"]["upstream"].update(recall=1),
        lambda r: r.update(decision_sha256="0" * 64),
        lambda r: r.update(schema_version=999),
        lambda r: r.update(cases=[]),
        lambda r: r.update(policy_configs={}),
        lambda r: r["results"][0].update(blocked="false"),
        lambda r: r["results"][0].update(latencies_ms=[float("nan")]),
        lambda r: r["results"][0].update(latencies_ms=[-1]),
        lambda r: r["results"][0].update(trajectory=[]),
        lambda r: r["results"][0].update(category="wrong"),
    ],
)
def test_invalid_report_rejected(report, mutation):
    bad = copy.deepcopy(report)
    mutation(bad)
    with pytest.raises(ValueError, match="invalid report"):
        compare(report, bad)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, 1.01])
def test_invalid_tolerance_rejected(report, value):
    with pytest.raises(ValueError, match="finite proportions"):
        compare(report, report, value)


@pytest.mark.parametrize("value", [None, [], {}, "not a report"])
def test_wrong_shape_rejected(value):
    with pytest.raises(ValueError, match="invalid report"):
        validate_report(value)


def test_committed_reports_are_consistent():
    for name in ("baseline", "mutations", "holdout"):
        validate_report(json.loads((ROOT / f"benchmarks/{name}.json").read_text()))


def test_real_configuration_change_is_incompatible(report):
    other = run(
        load_cases(ROOT / "corpus/cases.json"),
        RunConfig(repeats=1, policies=["disabled"]),
    )
    with pytest.raises(ValueError, match="incompatible reports"):
        compare(report, other)
