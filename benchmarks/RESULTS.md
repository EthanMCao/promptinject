# Measured benchmark results

The current firewall extension is recorded in [custom-firewall.json](custom-firewall.json).
On the same 40 original cases, custom input checks increase hostile blocks from
13/24 to 15/24 and benign blocks from 2/16 to 4/16. This shows the cost of the added
pattern rules. The earlier four-policy benchmark below is retained unchanged.

Generated from the checked-in JSON reports. These are synthetic firewall replay
results, not live LLM attack-success measurements. Timing is machine-specific.

| Campaign | Unique trials per policy | Upstream recall | Upstream FPR |
|---|---:|---:|---:|
| baseline | 40 | 54.2% (13/24) | 12.5% (2/16) |
| mutations | 136 | 51.2% (43/84) | 15.4% (8/52) |
| holdout | 12 | 37.5% (3/8) | 0.0% (0/4) |

## Original-payload baseline

| Policy | TP | FN | FP | TN | p50 ms | p95 ms |
|---|---:|---:|---:|---:|---:|---:|
| upstream | 13 | 11 | 2 | 14 | 0.516 | 1.060 |
| ingress_only | 6 | 18 | 2 | 14 | 0.490 | 1.051 |
| relaxed | 7 | 17 | 0 | 16 | 0.504 | 1.071 |
| disabled | 0 | 24 | 0 | 16 | 0.010 | 0.030 |

Hard-benign false-positive rate: **50.0% (2/4)**.

## Interpretation

- Output controls add coverage that ingress-only inspection does not provide.
- Relaxing the policy removes these false positives at the cost of recall.
- Multilingual, semantic, and direct-user attacks expose genuine fixture gaps.
- The mutation campaign skips inapplicable mutations; it does not manufacture
  extra samples for tool-only outputs or direct user inputs.
- The 12-case holdout is small and locally authored, not independent validation.

## Reproduction metadata

### baseline

- Corpus SHA-256: `ad722ce512a6bb95da8e32077c75813c9282dc57a2d09e356a9c2a727510aad5`
- Decision SHA-256: `00bffe70aa2a706a27ea7389a6ec976bcc796299883b371cc78d30b2a8a648ef`
- Platform source SHA-256: `bc3b29770201b015f2cf47223da56c7bdd42cba80013c5fcdd86cd4d08d66e69`

### mutations

- Corpus SHA-256: `ad722ce512a6bb95da8e32077c75813c9282dc57a2d09e356a9c2a727510aad5`
- Decision SHA-256: `9a243c7aff21522021eb0d7332000147ce596a7ea89a78c1df44909358ad40cc`
- Platform source SHA-256: `bc3b29770201b015f2cf47223da56c7bdd42cba80013c5fcdd86cd4d08d66e69`

### holdout

- Corpus SHA-256: `4730d37320f56d5971df21dc4368fb8ab34936e09634f2fdcdb1177b377ddc8d`
- Decision SHA-256: `68b8c9d867ddc717cbc84ca55af32a8800d08e6b1e043a7e336684e83bb4b1a0`
- Platform source SHA-256: `bc3b29770201b015f2cf47223da56c7bdd42cba80013c5fcdd86cd4d08d66e69`

Upstream commit: `f34a6c17ac84bca8cb515e979d7080bc8851e565`.
Runtime: Python 3.12.2; seed 42; three measured repeats.

Two separate original-payload baseline runs produced the same decision digest;
the regression gate passed. Latency values vary between runs.

See [methodology](../docs/METHODOLOGY.md) for definitions and limitations.
