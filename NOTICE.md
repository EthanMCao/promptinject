# Attribution and license notices

PromptInject Lab is a derivative platform distributed under **AGPL-3.0-or-later**.
The complete license is in `LICENSE`.

## Upstream foundation

- Author: Carter Perez / CarterPerez-dev; original files retain `©AngelaMos | 2026` notices.
- Repository: https://github.com/CarterPerez-dev/Cybersecurity-Projects
- Project: `PROJECTS/beginner/prompt-injection-firewall`
- Pinned commit: `f34a6c17ac84bca8cb515e979d7080bc8851e565`
- Upstream license: AGPL-3.0-or-later, preserved in `vendor/upstream/LICENSE`.
- Vendored subset: full Python source, upstream tests, benchmark corpus/runner,
  README, packaging metadata, and lockfile. Upstream frontend and deployment tooling
  are not incorporated. `vendor/manifest.json` records SHA-256 for every vendored file.
- **No vendored files were modified.** Runtime imports are through the original
  `not_sandboxed` package. This is substantive code reuse, not merely inspiration.

## Original additions

`promptinject/`, `corpus/`, `scripts/`, `tests/`, the root deployment configuration,
CI workflow, and platform documentation were created for Ethan Cao's project with
AI coding assistance in November 2026. They add original input rules and bounded Unicode/base64 views in `defenses.py`,
an interactive firewall API/playground in `scanner.py` and the frontend, plus the
replay scheduler, multi-turn
traces, metrics, policy comparison, regression gates, SQLite storage, API, dashboard,
and source packaging. They do not claim authorship of the upstream detection rules,
normalization, provenance fencing, tool authorization, or egress inspection.

## Distribution and network use

Keep this notice, both licenses, upstream copyright notices, and the manifest.
Provide the corresponding source and build instructions when distributing this
combined work. The dashboard links to `/source`, which serves a generated archive
of this project's corresponding source. `make source` refreshes it; the Docker
build generates it automatically. Regenerate after changing source. If operating
a modified version for remote users, maintain a prominent source offer and ensure
the downloadable archive matches that deployed version. Do not put a public
service behind an inaccessible or missing source link.

Dependencies are not vendored into the source archive. Their versions are pinned
in `requirements*.txt`; retain their package notices when redistributing installed
packages or container images. Upstream's `uv.lock` describes its full application,
not this platform's runtime. No upstream branding assets are reused.
