"""Original, explainable input rules added on top of CarterPerez-dev's firewall.

These deliberately small heuristics scan USER and DATA, never SYSTEM. They catch
some direct attacks that upstream's trusted-USER model does not inspect. They can
also block harmless quotations: matching a pattern is not proof of malicious intent.
"""

import base64
import binascii
import re
import time
from itertools import islice
import unicodedata
from dataclasses import dataclass

from not_sandboxed.context import Trust
from not_sandboxed.firewall import Firewall
from not_sandboxed.policy import decide
from not_sandboxed.verdict import Finding, Severity

RULESET_ID = "custom-input-v1"


@dataclass(frozen=True)
class Rule:
    id: str
    explanation: str
    pattern: str


RULES = (
    Rule(
        "instruction-override",
        "Asks the assistant to discard higher-priority instructions.",
        r"\b(?:ignore|disregard|forget|override)\b.{0,48}\b(?:previous|prior|earlier|system|developer)\b.{0,32}\b(?:instructions?|rules?|prompts?)\b",
    ),
    Rule(
        "prompt-extraction",
        "Asks for hidden system or developer instructions.",
        r"\b(?:reveal|show|print|repeat|output|display)\b.{0,48}\b(?:system|developer|hidden)\s+(?:prompts?|instructions?)\b",
    ),
    Rule(
        "role-impersonation",
        "Places a system/developer role marker inside lower-trust text.",
        r"(?:<\|im_start\|>\s*(?:system|developer)|\[(?:system|developer)\]|(?:^|\n)\s*###\s*(?:system|developer)\s*:)",
    ),
    Rule(
        "secret-request",
        "Requests a secret, password, API key, or access token.",
        r"\b(?:reveal|print|send|expose)\b.{0,48}\b(?:secret|password|api\s*key|access\s*token)\b",
    ),
)
COMPILED = [
    (rule, re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)) for rule in RULES
]
BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,4096}={0,2}(?![A-Za-z0-9+/=])"
)


def readable_views(text):
    """One normalization pass and up to four single-layer base64 decodes. No execution."""
    normalized = "".join(
        c
        for c in unicodedata.normalize("NFKC", text)
        if unicodedata.category(c) != "Cf"
    )
    views = [("original", text)]
    if normalized != text:
        views.append(("unicode-normalized", normalized))
    for token in islice(BASE64_TOKEN.finditer(normalized), 4):
        try:
            decoded = base64.b64decode(token.group(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeError):
            continue
        if decoded and decoded not in [body for _, body in views]:
            views.append(("base64-decoded", decoded))
    return views


def inspect_custom(ctx):
    findings = []
    for index, span in enumerate(ctx.spans):
        if span.trust is Trust.SYSTEM:
            continue
        matched = set()
        for view, text in readable_views(span.text):
            for rule, pattern in COMPILED:
                match = pattern.search(text)
                if match and rule.id not in matched:
                    matched.add(rule.id)
                    findings.append(
                        Finding(
                            layer="custom_ingress",
                            rule="custom:" + rule.id,
                            severity=Severity.HIGH,
                            invariant=True,
                            span_index=index,
                            evidence=f"{view}: {match.group()[:160]}",
                        )
                    )
    return findings


class CustomFirewall(Firewall):
    """Extend upstream input inspection; retain its provenance, tool, and output controls."""

    def inspect(self, ctx):
        started = time.perf_counter()
        upstream = super().inspect(ctx)
        if not self.policy.ingress_enabled:
            return upstream
        findings = (*upstream.findings, *inspect_custom(ctx))
        return upstream.model_copy(
            update={
                "findings": findings,
                "decision": decide(findings, self.policy),
                "elapsed_ms": (time.perf_counter() - started) * 1000,
            }
        )
