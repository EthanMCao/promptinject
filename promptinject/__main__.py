import argparse
import csv
import json
import sys
from pathlib import Path
from promptinject import ROOT
from promptinject.engine import load_cases, run, replay, policy_for
from promptinject.metrics import compare
from promptinject.models import RunConfig, ScanRequest
from promptinject.scanner import scan
from promptinject.store import Store


def main():
    parser = argparse.ArgumentParser(
        description="PromptInject Lab: deterministic firewall replay"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    bench = sub.add_parser("benchmark")
    bench.add_argument("--corpus", type=Path, default=ROOT / "corpus/cases.json")
    bench.add_argument("--output", type=Path, default=ROOT / "benchmarks/latest.json")
    bench.add_argument("--seed", type=int, default=42)
    bench.add_argument("--repeats", type=int, default=3)
    bench.add_argument("--variants", nargs="+", default=["original"])
    bench.add_argument(
        "--policies",
        nargs="+",
        default=["upstream", "ingress_only", "relaxed", "disabled"],
    )
    bench.add_argument(
        "--split", choices=["all", "development", "holdout"], default="all"
    )
    bench.add_argument("--save", action="store_true", help="Save to dashboard history")
    scanner = sub.add_parser(
        "scan", help="Inspect a prompt or output with both firewalls"
    )
    scanner.add_argument("text")
    scanner.add_argument("--source", choices=["user", "data"], default="user")
    scanner.add_argument("--stage", choices=["ingress", "egress"], default="ingress")
    inspect = sub.add_parser("inspect", help="Explain one built-in test case")
    inspect.add_argument("case_id")
    inspect.add_argument(
        "--policy",
        choices=["custom", "upstream", "ingress_only", "relaxed", "disabled"],
        default="upstream",
    )
    inspect.add_argument(
        "--variant",
        choices=["original", "base64", "zero_width", "quoted"],
        default="original",
    )
    check = sub.add_parser("compare")
    check.add_argument("baseline", type=Path)
    check.add_argument("candidate", type=Path)
    check.add_argument("--max-recall-drop", type=float, default=0)
    check.add_argument("--max-fpr-rise", type=float, default=0)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        if args.command == "serve":
            import uvicorn

            uvicorn.run(
                "promptinject.api:create_app",
                factory=True,
                host=args.host,
                port=args.port,
            )
        elif args.command == "scan":
            print(
                json.dumps(
                    scan(
                        ScanRequest(
                            text=args.text, source=args.source, stage=args.stage
                        )
                    ),
                    indent=2,
                )
            )
        elif args.command == "inspect":
            case = next(
                (
                    case
                    for case in load_cases(ROOT / "corpus/cases.json")
                    if case.id == args.case_id
                ),
                None,
            )
            if case is None:
                raise ValueError(f"unknown case: {args.case_id}")
            print(
                json.dumps(
                    {
                        "case": case.model_dump(),
                        "result": replay(case, args.variant, policy_for(args.policy)),
                    },
                    indent=2,
                )
            )
        elif args.command == "compare":
            if args.max_recall_drop < 0 or args.max_fpr_rise < 0:
                raise ValueError("tolerances must be nonnegative")
            failures = compare(
                json.loads(args.baseline.read_text()),
                json.loads(args.candidate.read_text()),
                args.max_recall_drop,
                args.max_fpr_rise,
            )
            print(json.dumps({"passed": not failures, "failures": failures}, indent=2))
            return 1 if failures else 0
        else:
            config = RunConfig(
                **{
                    k: getattr(args, k)
                    for k in ("seed", "repeats", "variants", "policies", "split")
                }
            )
            report = run(load_cases(args.corpus), config)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            with args.output.with_suffix(".csv").open("w", newline="") as file:
                fields = [
                    "policy",
                    "case_id",
                    "category",
                    "stage",
                    "split",
                    "variant",
                    "malicious",
                    "blocked",
                    "elapsed_ms",
                ]
                writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(report["results"])
            if args.save:
                Store(ROOT / "data/runs.sqlite3").save(report)
            for name, result in report["summaries"].items():
                print(
                    f"{name:14} TP={result['tp']} FN={result['fn']} FP={result['fp']} TN={result['tn']} p95={result['p95_ms']:.2f}ms"
                )
            print(f"Decision SHA256: {report['decision_sha256']}")
    except (ValueError, OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
