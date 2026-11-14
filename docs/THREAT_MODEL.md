# Threat model

## Boundaries

Untrusted document spans can contain arbitrary instructions. They enter the
upstream core as DATA with an explicit origin. Operator instructions enter as
SYSTEM; human input enters as USER. The upstream design trusts USER spans, so this
platform includes a direct-user hostile fixture to make that limitation visible.
The `custom` policy adds inspection of USER and DATA text with original rules; it
does not inspect SYSTEM spans or remove any upstream blocks.

Tool requests are inspected against a small registry: `search` (read-only) and
`send_email` (network egress, prohibited under untrusted influence). Unknown tools
are denied by upstream. Calls are never executed. Confirmation cannot be granted
by case content; the adapter fixes `user_confirmed=False`.

Egress uses a public synthetic canary. Its detection rate does not establish that
arbitrary sensitive data or paraphrased secrets will be stopped.

## Platform controls

- Loopback listener by default; Docker publishes only on 127.0.0.1.
- No caller-controlled provider URL, shell command, filesystem path, or corpus
  upload in the HTTP API.
- Strict input models reject unknown fields, unbounded counts, and large text.
- Playground scans accept at most 4,000 characters and never persist their inputs.
- One active web scan or evaluation per process. SQLite parameterizes queries and commits
  whole reports transactionally. Each operation owns its connection.
- Host allowlist and exact-origin checks on writes reduce DNS-rebinding and
  browser-driven cross-origin mutation. No CORS allowlist is configured.
- Payloads are rendered with textContent, not HTML. CSP and anti-framing headers
  restrict active content. No external frontend scripts or fonts.
- Source download is a fixed path; its deterministic archive excludes runtime
  data, caches, environment files, and local downloaded test wheels.

## Non-goals and residual risks

No authentication, per-user authorization, distributed job queue, or production
rate limiter. Host/origin checks are not authentication and do not stop local
programs. Request-body rejection occurs after framework parsing; do not expose
this app publicly without an authenticated proxy with body limits, TLS, and
rate limits. Only run one server worker; the run lock is process-local.

Inspection may be expensive for adversarially large or pathological text. Corpus
limits bound the CLI input, but synthetic corpus size and bounded variants are the
primary workload guard. SQLite history has no retention policy and will grow.
Do not import production secrets: raw evidence may be persisted and exported.

Pinned package versions make experiments repeatable, not automatically secure.
Review dependency advisories and update/test the lock before deploying to a shared
network. The recorded OSV scan covers pinned runtime and frontend-test packages and returned
no known advisories after updates. It does not cover the container OS, optional
Python test tools, or undisclosed vulnerabilities. See DEPENDENCY_AUDIT.json.

The platform detects neither every injection nor every harmful LLM behavior.
Ingress false positives and semantic evasions are visible in the baseline.
Real model evaluation requires independent outcome judges and task-utility
measurements; neither can be inferred from a blocked prompt alone.


## Custom input layer limitations

Four English regex rules run on original text, an NFKC view with format characters
removed, and up to four base64 token candidates of at most 4,096 characters.
Decoding is a single layer and never executes the decoded text. Nested encodings,
paraphrases, multilingual attacks, and attacks that avoid these patterns can pass.
Legitimate discussions and quotations of attacks can be blocked. Do not use this
layer as the only authorization or data-protection boundary. The egress and tool
checks are inherited from upstream, not newly implemented here.
