# Validation record

Expanded local verification: November 16, 2026 (America/Los_Angeles).

| Check | Observed result |
|---|---|
| Original platform Python tests | 81 passed, including original input-rule, scan API, trust-boundary, and failure tests |
| Frontend DOM unit tests | 10 passed; adds playground submission, source/stage controls, error recovery, and safe evidence rendering |
| Complete vendored upstream suite | 314 passed, including arena/proxy tests using test clients |
| Platform code coverage | Approximately 98% combined statement/branch coverage; not a detection-rate claim |
| Isolated Python environment | All declared dependencies installed; `pip check` found no broken requirements |
| Frontend dependency lock | `npm ci --offline --ignore-scripts` succeeded from integrity-verified cached tarballs |
| Dependency advisories | OSV returned no known advisories for 15 Python runtime packages and 9 frontend-test packages after updates |
| Cross-process determinism | Identical baseline decision hash under Python hash seeds 0, 1, and 42 |
| Current five-policy workload | 680 distinct trials, 13,600 measured replays; repeat comparison passed |
| Legacy four-policy workload | 544 distinct trials and 10,880 measured replays passed before the custom-layer addition |
| Source integrity | All 82 vendored files match SHA-256 manifest; upstream unchanged |
| Source distribution | Deterministic source archive includes all three dependency files; extracted-source benchmark reproduces baseline |
| API and persistence | In-process HTTP tests, same-origin restrictions, concurrent run rejection, rollback, restart persistence |
| Source safety | Environment files and symlinks excluded from corresponding-source archive |
| Static checks | Python undefined/unused-name checks and JavaScript syntax checks passed |
| Docker Compose | Configuration validates |
| Live server / browser | Sandbox denies listening on localhost; browser URL policy rejects local file URLs |
| Container build/runtime | Docker socket access denied; not verified here |
| Hosted CI | Workflow supplied; no hosted run claimed |

## Firewall extension verification

The original custom input layer catches direct-user override, extraction, forged-role,
and secret-request patterns, including tested base64 and Unicode forms. Tests check
that SYSTEM text is excluded, upstream blocks remain blocked, output checks remain
upstream's responsibility, decoding is bounded, and known false positives/evasions
remain visible. The scan endpoint does not persist input text and shares the
single-active-operation guard with replay runs.

On the frozen 40-case corpus, custom blocks 15/24 hostile and 4/16 benign cases;
upstream blocks 13/24 hostile and 2/16 benign cases. Both custom and legacy benchmark
regression gates pass. This is a local tradeoff, not a claim of general superiority.

## Issues found and fixed

- Publication review caught a source-archive filter that excluded `.txt` dependency
  manifests. It now includes them; the archive test verifies all three requirement
  files byte-for-byte, so a fresh checkout can install the declared dependencies.
- The API documentation used external and inline scripts blocked by the CSP.
  It now uses a small local reference page generated from the OpenAPI schema.
- The comparison gate trusted summaries even when evidence was missing or altered.
  It now validates source cases, trial completeness, labels, timing samples,
  trajectory decisions, recomputed metrics, and hashes.
- NaN/infinite regression tolerances could disable meaningful comparisons.
  Tolerances must now be finite proportions between zero and one.
- SQLite connections relied on cleanup by garbage collection. Connection handling
  now explicitly commits/rolls back and closes the connection.
- The initial runtime lock had advisories for Starlette, AnyIO, and IDNA.
  Compatible dependency updates were installed and retested. The full scan result
  and its limited scope are in [DEPENDENCY_AUDIT.json](DEPENDENCY_AUDIT.json).
- The original Python packaging metadata implied a standalone wheel but omitted
  runtime source assets. The project now explicitly supports running from a source
  checkout/archive; unnecessary wheel packaging was removed.

## Repeat the checks

```bash
source .venv/bin/activate
python -m pytest --cov=promptinject --cov-branch --cov-report=term-missing
npm ci --ignore-scripts
npm test
python scripts/verify_benchmarks.py

# Optional: complete upstream suite, without changing vendored files
python -m pip install -r requirements-upstream-tests.txt
PYTHONPATH=vendor/upstream/src:vendor/upstream python -m pytest -q vendor/upstream/tests \
  --basetemp=artifacts/upstream-pytest
```

Python tests were run on Python 3.12.2; frontend tests used Node 24.3.0. The
project's `.venv` is isolated from system site packages. Downloaded wheels and npm
tarballs were verified against registry hashes before offline installation.

## What remains unverified

A DOM emulator verifies application logic, not actual browser layout, CSP
implementation, accessibility behavior, or networking. The recorded-response
browser fixture is available via `scripts/build_browser_fixture.py`, but browser
policy prevented opening it here. A real browser and Docker smoke test must still
be run in an environment that allows listening sockets/container access.

The project does not call real LLMs or execute model-requested tools. There is no
claim of live-model attack-success reduction, production readiness, or complete
security. Optional Python test packages and the container's OS are outside the
recorded dependency-audit scope. Test coverage is not proof of correctness for
all possible inputs.
