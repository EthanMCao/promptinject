# Resume and interview guide

The project is a **prompt-injection firewall**, built on an attributed open-source
foundation. The replay dashboard supports testing the firewall; it is not the main
project claim. Read [FIREWALL_DESIGN.md](FIREWALL_DESIGN.md) for how the defenses work.

## Suggested resume entry

**PromptInject — LLM Prompt Injection Firewall** | Python, FastAPI, Docker

- Extended an open-source prompt-injection firewall with explainable rules for
  instruction override, prompt extraction, role impersonation, and secret requests.
- Added Unicode/base64 input inspection and an interactive interface showing
  matched rules, trust boundaries, and input/output blocking decisions.
- Built automated tests and attack replay to measure missed attacks and false
  positives across 40 synthetic attack and benign cases.

Use these bullets once you can run, explain, and modify the code. They describe the
project's additions without claiming authorship of the reused foundation. This
implementation was developed with AI assistance, as recorded in NOTICE.md.

## A natural interview explanation

> I built on an open-source LLM prompt-injection firewall and added my own input
> checks and a playground to understand the attacks. For example, a direct user
> message can ask the assistant to ignore its instructions or reveal its system
> prompt. My added layer checks those patterns, including some obfuscated forms.
> I also tested harmless quotations because stricter detection can block legitimate
> text. The project shows both the successful blocks and the cases it gets wrong.

If asked what was already provided, say: "The existing firewall supplied provenance,
output filtering, tool authorization, and its original detector. My extension adds
custom input rules, the interactive inspection flow, and the tests around them."

## Five-minute demo

1. Submit the instruction-override example as a USER message. Explain upstream ALLOW
   versus custom BLOCK and read the matching rule.
2. Select the base64 example. Show the decoded text and the same rule firing.
3. Change the source to a retrieved document. Explain DATA provenance and fencing.
4. Inspect the outgoing fake secret. Credit upstream's egress layer for the block.
5. Try the harmless quotation. Explain why the custom rule also blocks it, then
   show the benchmark: 15/24 hostile blocked and 4/16 benign blocked, compared with
   upstream's 13/24 and 2/16. This is a small local experiment, not a production claim.

Avoid saying "built the entire firewall from scratch," "trained an AI detector,"
or "secured a production LLM." The honest extension is already a useful student
security project; you do not need those claims.
