# AI Deep SAST Plugin Development Guide

> **Status: SCAFFOLD / PRE-SPEC.** This document captures the architecture-fit
> analysis and the plugin requirements for integrating
> [cisco-open/ai-deep-sast](https://github.com/cisco-open/ai-deep-sast) into ASH
> as a community scanner plugin. The scanner implementation, bundled config,
> README, tests, and user docs are **not yet written** — they will be produced
> from the spec that follows this document.

This guide is for maintainers working on the ASH AI Deep SAST plugin. It mirrors
the structure of the [ferret-scan plugin DEVELOPMENT.md](../ash_ferret_plugins/DEVELOPMENT.md),
which is the reference implementation for community scanner plugins.

## Table of Contents

- [Tool Summary](#tool-summary)
- [Fit Analysis](#fit-analysis)
  - [Mechanical Plugin-Architecture Fit](#mechanical-plugin-architecture-fit)
  - [General-Design Fit](#general-design-fit-ash-philosophy)
  - [Verdict](#verdict)
- [Plugin Requirements](#plugin-requirements)
- [Planned File Structure](#planned-file-structure)
- [Proposed Configuration Options](#proposed-configuration-options)
- [SARIF Conversion Requirement](#sarif-conversion-requirement)
- [Security Considerations](#security-considerations)
- [Open Questions for the Spec](#open-questions-for-the-spec)
- [Value Proposition](#value-proposition)
- [Competition & Overlap With Existing ASH Plugins](#competition--overlap-with-existing-ash-plugins)
- [Architecture Decision: Plugin vs. Cross-Cutting Triage Layer](#architecture-decision-plugin-vs-cross-cutting-triage-layer)
- [Local Model: Foundation-Sec-8B](#local-model-foundation-sec-8b)
- [How ASH Provisions Tools](#how-ash-provisions-tools-and-the-model-weights-gap)
- [Provisioning, UX, and Supply-Chain Security](#provisioning-ux-and-supply-chain-security)
- [Alternatives Evaluated](#alternatives-evaluated)
- [References](#references)

## Tool Summary

`ai-deep-sast` is a Python, LLM-augmented SAST tool published by Cisco under
**Apache-2.0** (compatible with ASH's Apache-2.0 license).

**Pipeline** (`aideepsast.py`):

1. Runs **semgrep** (`semgrep --json`, default ruleset `p/owasp-top-ten`).
2. Performs a **tree-sitter** "deep scan" across ~16 languages
   (`detector.py`, `deepscan.py`, `indexer.py`, `rule_matcher.py`).
3. Sends candidate findings/code to an **LLM** for triage/analysis
   (`triager.py`, `llm_client.py`).
4. Emits a custom **`owasp_ai_report.json`** (via `generate_json_report`) plus a
   text report (`deepscan_reporter.py`). **No SARIF output.**

**LLM configuration** (`llm_client.py`) — two paths:

- **Remote, OpenAI-compatible API**: environment-driven via `LLM_BASE_URL`
  (default `https://api.openai.com/v1`), `LLM_MODEL` (default `gpt-4o`), and an
  API-key environment variable. Works with OpenAI/Azure/Anthropic-via-proxy/
  Ollama/vLLM/LiteLLM.
- **Local GGUF model via llama.cpp**: Cisco's `Foundation-Sec-8B` (default repo
  `fdtn-ai/Foundation-Sec-8B-Q8_0-GGUF`, ~8 GB), controlled by `--hf-repo`,
  `--hf-file`, `--ctx-size`, `--n-gpu-layers`, `--threads`.

There is also a **`--skip-llm`** mode that runs semgrep only.

**Invocation note:** the tool is run as `python3 aideepsast.py ...` from a repo
checkout. It is **not** published to PyPI as a console entry point (unlike
ferret-scan's `ferret-scan` command). Install/invocation strategy is an open
question (see below).

**CLI surface** (`aideepsast.py` argparse): `--target`, `--output-dir`,
`--severity-threshold {INFO,WARNING,ERROR}`, `--semgrep-config`,
`--semgrep-timeout`, `--llm-timeout`, `--skip-llm`, `--skip-llm-rules`,
`--config`, `--log-level`, `--log-file`, plus the local-model flags listed above.

**Dependencies** (`requirements.txt`): `semgrep`, `pyyaml`, `tree-sitter` +
~16 language grammars, `openai`. The local-model path additionally needs a
llama.cpp runtime and the ~8 GB model download.

## Fit Analysis

### Mechanical Plugin-Architecture Fit

Against the `ScannerPluginBase` contract (a subprocess-driven CLI scanner that
ASH aggregates), the tool fits **with one significant adapter**:

| Aspect | Fit | Notes |
|--------|-----|-------|
| CLI, subprocess-invokable | ✅ | `--target`, `--output-dir`, `--severity-threshold`, etc. — wrappable like `ferret_scanner.py`. |
| License | ✅ | Apache-2.0, eligible as a community plugin module. |
| SARIF output | ❌ | Tool emits `owasp_ai_report.json`, not SARIF. **The plugin must convert JSON → SARIF** (the main mechanical task; ferret had this for free). |
| Install/invocation | ⚠️ | No console entry point; `python3 aideepsast.py`. UV-tool integration (as semgrep/checkov use) does not directly apply. |

No blocker at the architecture layer, but the SARIF converter and the
install/invocation strategy are net-new work relative to ferret.

### General-Design Fit (ASH philosophy)

ASH targets offline-capable, deterministic, fast, lightweight, CI-gating scans.
The tool collides with several of these:

| ASH principle | `ai-deep-sast` reality | Severity |
|---|---|---|
| Offline / airgapped (`ASH_OFFLINE`) | Default path needs a **remote LLM** + API key. Offline only via the local ~8 GB GGUF model. | High |
| No data egress (proprietary code) | Remote mode **sends source code to a third-party LLM** — a serious posture concern for a security scanner. | High |
| Deterministic / reproducible gating | LLM triage is non-deterministic (default temperature 0.1) → flaky pass/fail. | High |
| Fast & free | Per-scan **LLM latency + cost** (`llm_client.py` tracks estimated USD). | Medium |
| Lightweight container | semgrep + 16 tree-sitter grammars + openai, and optionally llama.cpp + ~8 GB model. | Medium |
| Non-overlapping scanners | It **re-runs semgrep**, which ASH already ships (`semgrep`/`opengrep`) → duplicate findings. | Medium |
| SARIF aggregation | Custom JSON; needs a converter. | Low/Medium |

### Verdict

The tool **can** be wrapped as a community scanner plugin, but as-is it is a poor
fit for ASH's core design. It fits cleanly only when scoped as an
**explicitly opt-in, non-default, non-gating "augmentation" scanner**. The
recommended shape (to be confirmed in the spec) is **local-model-first /
informational-severity**, so ASH's offline and no-egress promises are preserved
by default and remote-LLM usage is an explicit, well-documented opt-in.

## Plugin Requirements

These are the requirements the spec and implementation must satisfy.

### R1 — Community plugin module
- Module: `automated_security_helper.plugin_modules.ash_ai_deep_sast_plugins`.
- `__init__.py` exports `ASH_SCANNERS = [AiDeepSastScanner]` and `ASH_REPORTERS = []`.
- Scanner config `name` literal: **`ai-deep-sast`**; `tool_type = SAST`.
- Registered in `.ash/.ash_community_plugins.yaml` (NOT `.ash/.ash.yaml`) and
  added to `ash_plugin_modules`. Opt-in by module inclusion, like ferret-scan.

### R2 — Mode selection (offline/egress safety is the core requirement)
- Support a `mode` option: `local` (llama.cpp + Foundation-Sec model),
  `remote` (OpenAI-compatible API), and `skip-llm` (semgrep only).
- **In `ASH_OFFLINE`, `remote` mode MUST be refused** in
  `validate_plugin_dependencies()` (no network egress in offline mode). Only
  `local` or `skip-llm` may proceed offline.
- Recommended default: `local` (or `skip-llm` if no model present), never
  silently `remote`.

### R3 — SARIF conversion
- The plugin MUST translate `owasp_ai_report.json` → SARIF (the tool has no
  native SARIF output). Map finding id, severity (INFO/WARNING/ERROR →
  SARIF level/ASH severity), message, file path, and line/region. Validate the
  produced SARIF through ASH's Pydantic SARIF model (as ferret does for its
  native SARIF).

### R4 — ASH-managed concerns (hardcoded, not user-configurable)
- Output directory: ASH convention `.ash/ash_output/scanners/ai-deep-sast/`.
  The plugin sets `--output-dir` to the ASH-managed location.
- Suppressions: managed centrally by ASH; do not use any tool-side suppression.
- Logging: ASH controls log level. Use an `ai_deep_sast_*` prefix for any option
  that toggles the tool's own log verbosity (mirror ferret's `ferret_debug`
  pattern to avoid clashing with ASH's `--debug`/`--verbose`).

### R5 — Secrets handling
- The LLM API key is read from its environment variable only. It MUST NOT be
  accepted in plugin config, written to any file, or logged.

### R6 — Determinism & severity posture
- Default `temperature` to `0` (tool default is 0.1) to reduce nondeterminism.
- Default the plugin's findings to **informational / non-build-failing**, given
  LLM nondeterminism. Allow opt-in gating via `severity_threshold`.

### R7 — Semgrep overlap
- Document that with `--skip-llm` the tool is largely redundant with ASH's
  built-in `semgrep`/`opengrep` scanners. The differentiated value is the LLM
  triage / deep-scan. Consider how to avoid double-reporting semgrep findings
  (e.g., rely on ASH's existing semgrep scanner and run this tool only for its
  LLM-triaged deep-scan findings) — to be decided in the spec.

### R8 — Version compatibility
- Pin a tested commit/tag of `ai-deep-sast` (it has no semver releases on PyPI).
  Mirror ferret's version-constant + compatibility-check approach adapted to a
  git ref rather than a PyPI version.

### R9 — Tests & docs (post-spec)
- Unit tests under `tests/unit/plugin_modules/ash_ai_deep_sast_plugins/`.
- User docs: `README.md` here + `docs/content/docs/plugins/community/ai-deep-sast-plugin.md`,
  and update `docs/content/docs/plugins/community/index.md`.

## Planned File Structure

```
automated_security_helper/
└── plugin_modules/
    └── ash_ai_deep_sast_plugins/
        ├── __init__.py                  # ASH_SCANNERS / ASH_REPORTERS  (TODO: post-spec)
        ├── ai_deep_sast_scanner.py      # Scanner implementation        (TODO: post-spec)
        ├── ai-deep-sast-config.yaml     # Bundled tool config (if used) (TODO: post-spec)
        ├── README.md                    # User documentation            (TODO: post-spec)
        └── DEVELOPMENT.md               # This file

tests/
└── unit/
    └── plugin_modules/
        └── ash_ai_deep_sast_plugins/    # Unit tests                    (TODO: post-spec)

docs/
└── content/
    └── docs/
        └── plugins/
            └── community/
                ├── index.md             # Add ai-deep-sast entry        (TODO: post-spec)
                └── ai-deep-sast-plugin.md  # Full user docs             (TODO: post-spec)
```

## Proposed Configuration Options

Draft for the spec to refine. Modeled on `FerretScannerConfigOptions`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mode` | `local` \| `remote` \| `skip-llm` | `local` | LLM execution mode. `remote` is refused in offline mode. |
| `severity_threshold` | `INFO` \| `WARNING` \| `ERROR` | `WARNING` | Minimum severity passed through (maps to tool `--severity-threshold`). |
| `semgrep_config` | string | `p/owasp-top-ten` | Semgrep ruleset for the tool's internal semgrep pass. |
| `semgrep_timeout` | int | tool default | Seconds for the semgrep pass. |
| `llm_timeout` | int | tool default | Seconds per LLM call. |
| `skip_llm_rules` | string | tool default | Comma-separated rule prefixes to skip LLM triage for. |
| `temperature` | float | `0` | LLM sampling temperature (0 for determinism). |
| `max_tokens` | int | tool default | Max LLM generation tokens. |
| `model` | string | env `LLM_MODEL` | Remote model name (remote mode). API key/base URL stay in env, never config. |
| `hf_repo` / `hf_file` | string | tool default | Local GGUF model source (local mode). |
| `ctx_size` / `n_gpu_layers` / `threads` | int | tool default | Local-model runtime tuning. |
| `tool_ref` | string | pinned ref | Git ref/commit of ai-deep-sast to use. |
| `ai_deep_sast_debug` | bool | `false` | Tool's own debug logging (prefixed to avoid clashing with ASH `--debug`). |

Unsupported / blocked options (Pydantic `mode="before"` validator, like ferret):
- Any raw `output-dir`/`output_dir` (ASH-managed).
- Bare `debug`/`verbose` (use `ai_deep_sast_debug`).
- Any tool-side suppression options (ASH manages suppressions).

## SARIF Conversion Requirement

This is the single biggest implementation difference from ferret-scan, which
emits SARIF natively. For ai-deep-sast the plugin owns the conversion:

1. Run the tool with `--output-dir <ash-managed-dir>`.
2. Read `owasp_ai_report.json` from that directory.
3. Map each finding to a SARIF result: `ruleId`, `level`
   (INFO→note, WARNING→warning, ERROR→error), `message.text`, and
   `physicalLocation` (`artifactLocation.uri` + `region.startLine`).
4. Emit a SARIF run with `tool.driver.name = "ai-deep-sast"` and the tool
   version/ref, then validate via ASH's SARIF Pydantic model and attach scanner
   details (see `automated_security_helper.utils.sarif_utils`).
5. Return per the scanner return contract (validated `SarifReport`, or a
   `ScanResultsContainer` with `.sarif_report`).

The exact `owasp_ai_report.json` schema must be captured during the spec by
running the tool against the bundled `samples/` in the upstream repo.

## Security Considerations

- **Data egress (remote mode):** source code is sent to an external LLM. This
  must be a loud, explicit opt-in with a prominent warning (stronger than
  ferret's `show_match` warning), and disabled under `ASH_OFFLINE`.
- **API key:** environment-only; never logged or persisted.
- **Subprocess safety:** build argument lists (no `shell=True`), mirroring
  ferret. Validate any user-supplied paths before passing them through.
- **Cost:** remote mode incurs per-token cost; surface the tool's cost estimate
  in logs and document it.
- **Non-determinism:** LLM output varies run-to-run; default to informational
  severity to avoid flaky CI gating.

## Open Questions for the Spec

1. **Install/invocation:** vendor a pinned checkout, `pip install` from a git
   ref, or require a user-provided path to `aideepsast.py`? (No PyPI console
   entry point exists.)
2. **Default mode:** `local` vs `skip-llm` when no model is present. How is the
   ~8 GB model provisioned in the ASH container vs. local runs?
3. **Semgrep de-duplication:** suppress the tool's semgrep pass and rely on ASH's
   semgrep scanner, or keep it and de-dupe in the SARIF converter?
4. **Container footprint:** is the local model in-scope for the ASH image, or
   local/CI-only with the container limited to `skip-llm`/`remote`?
5. **`owasp_ai_report.json` schema:** finalize the field mapping to SARIF from a
   real run against upstream `samples/`.
6. **Severity mapping:** confirm INFO/WARNING/ERROR → ASH severity + SARIF level.
7. **HF repo gating:** verify `fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF` is
   ungated (appears public, with third-party mirrors/fine-tunes) so programmatic
   download needs no token; otherwise a one-time license acceptance + HF token is
   required.
8. **Pinning baseline:** record the HF repo **commit SHA** and the GGUF
   **SHA-256**, plus the pinned llama.cpp release (and its checksum) /
   `llama-cpp-python` version, as the verified supply-chain baseline.
9. **Inference runtime choice:** `llama-completion` CLI (matches upstream, needs
   prebuilt-binary provisioning) vs `llama-cpp-python` (pip-installable, best UX,
   but may compile llama.cpp at install). Decide which the plugin depends on.
10. **Advisory vs gating:** confirm LLM verdicts are advisory-only by default
    (never auto-suppress) to contain prompt-injection risk from scanned code.

## Value Proposition

`ai-deep-sast`'s value is **not detection breadth** — that comes from semgrep,
which ASH already ships. Its value is the **AI reasoning layer on top of
detection** (grounded in `triager.py`, `deepscan.py`, `rule_matcher.py`, and the
upstream README):

1. **Evidence-gated triage / false-positive reduction (the headline value).**
   `triager.py` investigates each candidate finding — reads the code at the
   location, traces data flow (callers → function → callees), checks
   sanitization/validation, identifies trust-boundary crossings, assesses
   exploitability — then assigns a verdict (`true-positive`, `false-positive`,
   `needs-review`, `not-applicable`, `code-quality`) and surfaces only survivors.
   No ASH scanner does semantic triage today; ASH aggregates raw hits and relies
   on thresholds/suppressions. Industry context: a large share of raw SAST
   results are false positives, and published AI-triage studies report large FP
   reductions. (Content rephrased for licensing compliance.)
2. **Whole-codebase deep scan** (`deepscan.py`): tree-sitter indexing + a
   frontier model for cross-function/cross-file reasoning that pattern rules
   miss. README notes ~30 min to ~14 h depending on mode (a major latency
   signal).
3. **Remediation + explanation per finding**: OWASP category, corrected-code
   remediation, and CWE/OWASP references.
4. **Standards mapping** (`rule_matcher.py`): ASVS 5.0 + CodeGuard patterns — a
   compliance overlay ASH does not produce today.

Caveats: triage is itself LLM-produced (nondeterministic; can wrongly suppress a
real finding); its quality scales with model size (which pushes toward
frontier/remote = egress); the deep mode's runtime is unsuitable for CI gating.

## Competition & Overlap With Existing ASH Plugins

ASH scanner roster — **SAST:** bandit, semgrep, opengrep; **IaC:** cdk-nag,
cfn-nag, checkov; **SCA:** grype, npm-audit; **SBOM:** syft; **Secrets:**
detect-secrets. Community: ferret-scan (PII), snyk, trivy.

`ai-deep-sast` is a **SAST** tool, so overlap is confined to the SAST lane:

- **Direct overlap — semgrep (built-in):** `ai-deep-sast` literally runs semgrep
  internally (`semgrep --json`, default `p/owasp-top-ten`). If both are enabled,
  its semgrep findings **duplicate** ASH's semgrep scanner (see Requirement R7).
- **opengrep** (a semgrep fork) and **bandit** (Python) overlap in the same SAST
  space.
- **Incidental:** a few hardcoded-credential rules touch the
  detect-secrets/ferret space.
- **No overlap:** IaC, SCA, SBOM.

**It does not replace any built-in** — those are deterministic, fast, free, and
offline; `ai-deep-sast` is non-deterministic, slower, and (in remote mode)
costlier. It **augments** a SAST baseline rather than reproducing the others.
Practical implication: de-duplicate against ASH's semgrep — either rely on ASH's
semgrep scanner and consume only the LLM-triaged deep-scan output, or de-dupe in
the SARIF converter.

## Architecture Decision: Plugin vs. Cross-Cutting Triage Layer

ASH runs **convert → scan → report** phases, normalizes every scanner's output
into one aggregated SARIF model, and exposes lifecycle event subscribers
including **`SCAN_PHASE_COMPLETE`** (fires after all scanners finish, before
reporting — see `automated_security_helper/plugins/events.py`). That makes the
triage/enrichment value naturally **cross-cutting**: it operates on
*findings + code*, which ASH already has for **every** scanner.

- The tool's **detection** belongs as a scanner plugin — but it largely
  duplicates the existing SAST scanners.
- The tool's **differentiated value (triage/enrichment)** is best as a
  **post-scan layer** — an event subscriber on `SCAN_PHASE_COMPLETE` (or a new
  phase) that reads the aggregated SARIF + source and annotates/triages findings
  from *all* scanners. This is post-scan processing, not detection, which
  reinforces the scanner-vs-reporter distinction.

**No retraining is needed to span other scanners.** The model is a general
code-reasoning model; scanners are just finding sources. Supporting
bandit/checkov/grype findings is prompt/harness work (normalize the finding,
build code context, apply per-finding-type evidence gates), not weight
retraining. Triage quality varies by finding class: SAST data-flow triage
generalizes well; SCA (CVE reachability) and secrets ("real vs. placeholder")
are different reasoning tasks; the model's April-2025 knowledge cutoff weakens
novel-CVE triage (supplement via RAG / feeding advisory data into the prompt).

**Important nuance:** `ai-deep-sast` is not built to ingest *foreign* findings —
its triager reads its own finding store populated by its own semgrep/deep-scan.
So "progressively add other plugins to it" really means **building an ASH-native
triage layer that reuses its pieces** (its prompts, the model, and
`llm_client.py`/`triager.py` are Apache-2.0 and liftable), not bolting other
scanners onto the upstream tool.

**Recommended phasing:**

- **Phase 1 (the current scaffold):** ship `ai-deep-sast` as an opt-in community
  scanner. Low risk; it validates the reusable hard parts — model/install
  provisioning, offline gating, the JSON→SARIF mapping, prompt behavior, and the
  real cost/latency profile.
- **Phase 2:** extract an **ASH-native cross-cutting AI triage/enrichment layer**
  on `SCAN_PHASE_COMPLETE`, reusing Phase 1's model harness and prompts.

**Governance caveat:** *enrichment* (adding remediation, CWE/OWASP/ASVS, and
exploitability context) is low-risk and additive; *suppression* (acting on
`false-positive`/`not-applicable` verdicts to hide findings) changes ASH's
"surface everything, suppress only explicitly" stance — especially via a
nondeterministic LLM across all scanners. Default any cross-cutting triage to
**advisory** (annotate confidence/verdict; do not auto-hide) until proven.

## Local Model: Foundation-Sec-8B

Committing to the local model is the recommended path for ASH-fit.

- **Provenance / license:** `Foundation-Sec-8B-Instruct` (Cisco Foundation AI,
  released 2025-08-01) is an **open-weight** 8B model built on a **Meta
  Llama-3.1-8B** backbone (`config.json` → `LlamaForCausalLM`). It is
  **dual-licensed** (`NOTICE.md`): the Llama base under the **Llama 3.1
  Community License** (Meta), Cisco's changes under **Apache 2.0**. So it is
  open-weight but **not fully permissive** — the Llama 3.1 Community License
  imposes acceptable-use terms, a "Built with Llama" attribution requirement, a
  >700M-MAU clause (separate Meta license at that scale), and a restriction on
  using outputs to train competing non-Llama models. **Bundling/redistributing
  the weights in the ASH image requires license compliance and likely legal
  sign-off**; fetching at runtime shifts that obligation to the user.
- **Benefits:** **no data egress** (source code stays local — the single biggest
  ASH-fit win); **offline/airgapped-capable**; **no per-scan API cost**;
  **reproducible** (pinned weights + `temperature=0`); **security-specialized**
  (the model card reports +3 to +11 points over generic Llama-3.1-8B on security
  benchmarks and competitiveness with GPT-4o-mini on security tasks); supports
  data sovereignty/compliance.
- **Costs:** ~8 GB model + inference compute (GPU strongly preferred; CPU is
  slow); April-2025 knowledge cutoff; sub-frontier quality.
- **Impact on the design tensions:** choosing local resolves the three
  High-severity tensions — **offline, data egress, and cost** — which flips the
  tool from "conflicts with ASH design" to "**compatible** with it." Footprint +
  compute becomes the central problem. Standard CI runners are CPU-only, so
  per-finding 8B inference is likely impractical for PR-gating CI → better suited
  to local/dedicated/GPU runs.
- **Scoping consequence:** upstream uses the **local 8B for fast per-finding
  triage** and a **frontier model for the whole-codebase deep scan**. Local-only
  ⇒ you keep the per-finding triage/enrichment value (which is exactly the
  cross-cutting use case) and drop/weaken the ~14-hour frontier deep scan — a
  good fit that also removes the worst latency concern.

## How ASH Provisions Tools (and the Model-Weights Gap)

ASH is fundamentally an orchestrator, but it has **three** tool-provisioning
models — not just "install everything separately":

1. **ASH auto-installs (UV tool integration):** pip/uvx CLIs are installed and
   version-managed by ASH (`use_uv_tool=True`; built-ins checkov, semgrep,
   bandit, via `uv_tool_mixin` / `uv_tool_runner`).
2. **Plugin-declared install commands:** `get_installation_commands(platform,
   arch)` are executed by `ash dependencies install` (e.g., the opengrep
   download); this is how the container provisions binaries at build time.
3. **Pre-installed / baked-in:** community plugins like ferret-scan are
   **check-only** — `validate_plugin_dependencies()` calls `find_executable()`
   and errors with manual-install instructions if missing; the official ASH
   container bakes in non-pip tools (grype, syft, trivy, cfn-nag, node) at Docker
   build time. "Installed separately" is most accurate for community plugins in
   host/local mode.

For `ai-deep-sast`: it runs as `python3 aideepsast.py` from a repo checkout (no
PyPI console entry point), so UV-tool integration does not apply cleanly —
provision via install-commands (pip from a pinned git ref + its requirements) or
check-only. **The ~8 GB model weights fall outside all three models** — ASH has
no model-artifact provisioning primitive. So the weights are bespoke: runtime
Hugging Face download, pre-mounted/cached (required for airgapped), or
image-baked (not in the main ASH image). This, plus the Llama license, are the
central local-model decisions for the spec.

## Provisioning, UX, and Supply-Chain Security

### Concrete local-model install flow (verified against upstream)

The tool shells out to **`llama-completion`** (a **llama.cpp** CLI binary), which
downloads the GGUF from Hugging Face via `--hf-repo`/`--hf-file` and caches it
(~8 GB). It does **not** use a Python binding. There are **three dependency
layers**:

1. **Python deps** — `pip install -r requirements.txt` (semgrep, tree-sitter +
   ~16 grammars; `openai` only matters for the remote/frontier path).
2. **Inference runtime** — the llama.cpp `llama-completion` binary
   (`brew install llama.cpp`, prebuilt release binaries, or build from source).
   **Not a pip package.**
3. **GGUF weights (~8 GB)** — fetched + cached on first run
   (`fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF` /
   `foundation-sec-8b-instruct-q8_0.gguf`); ~10–20 GB free disk; GPU
   (Apple Metal / NVIDIA CUDA, `-ngl -1`) recommended, CPU works but is slow.

At scan time the plugin subprocesses `llama-completion` per finding
(`-c <ctx> -ngl <gpu_layers>`) and parses the verdict.

### Runtime decision: `llama-completion` CLI vs `llama-cpp-python`

- **CLI (`llama-completion`)** — matches upstream exactly, but the binary is not
  pip-installable; provision via prebuilt release download
  (`get_installation_commands`, the grype/syft/trivy pattern) or `brew`.
- **`llama-cpp-python`** — pip-installable, bundles llama.cpp, and exposes
  `Llama.from_pretrained(repo_id, filename)` (downloads the GGUF from HF). This
  collapses layers 2+3 into a single pip path and is cross-platform, at the cost
  of the plugin owning the inference call instead of subprocessing the upstream
  CLI. **Caveat:** it may compile llama.cpp at install (needs a C/C++ toolchain —
  same `build-essential` concern as the Dockerfile investigation) unless a
  prebuilt wheel is used.

### User experience / complexity

Relative to a typical community scanner (`pip install <tool>`, one binary), the
local-model path is **materially heavier**: three layers + ~8 GB model + GPU for
usable speed + slow first-run download. This inherent cost (8 GB / GPU /
inference latency) cannot be polished away.

Verdict: **acceptable only as an explicitly opt-in, advanced, local-AI plugin** —
never a default scanner, and unsuitable for CPU-only PR-gating CI. UX can be made
*acceptable* (not trivial) via: a single `ash dependencies install` path
(pip + prebuilt llama.cpp + pre-pull GGUF); strong preflight checks with
actionable errors (missing layer, disk space, GPU-vs-CPU detection) and a clean
skip when the model is absent; and preferring the `llama-cpp-python` route for
the smoothest cross-platform install. This complexity is also an argument for the
Phase-2 cross-cutting design: centralize it once in an ASH-managed triage layer
rather than re-solving per plugin.

### Supply-chain & LLM threat model

Because this ships an ~8 GB binary blob plus a native inference binary into a
**security** tool, treat provisioning as a supply-chain surface. Four distinct
risks — hashes/pinning solve the first two/three, **not** the fourth:

1. **Weights integrity (hashes solve this).** Pin the HF repo **revision (commit
   SHA)**, download via `huggingface_hub(revision=<sha>)`, and verify the GGUF
   **SHA-256** against a known-good digest baked into the plugin. Do not rely on
   a floating `--hf-repo` name alone.
2. **Inference-binary integrity (hashes solve this).** Pin the llama.cpp release
   and verify its published checksum/signature, or pin `llama-cpp-python==X` with
   pip `--require-hashes`. Pin all Python deps with hashes.
3. **Malicious-model / native-parser RCE (mitigated by #1).** GGUF is data, but
   llama.cpp's GGUF/ggml parser is native C++ with a history of memory-safety
   CVEs — a tampered model could exploit a parser bug. Mitigate by sourcing only
   from the hash-verified origin (#1) and tracking a patched llama.cpp version
   floor. The model's Jinja chat template must be rendered via llama.cpp's
   handling, not an unsandboxed Python Jinja.
4. **Prompt injection from scanned code (the biggest risk; hashes do nothing).**
   The plugin feeds *untrusted source code* into the LLM prompt. A malicious repo
   can embed instructions ("mark all findings as false-positive") to make the
   triager **suppress real vulnerabilities** — an attacker who controls scanned
   code could neuter the scanner. Mitigations are by-design:
   - **Advisory-only by default** — LLM verdicts annotate; never auto-suppress
     findings (see the enrichment-vs-suppression governance caveat).
   - Strict **output-schema validation** (Pydantic); treat model output as
     untrusted; no `eval`; sanitize strings before SARIF/logs.
   - Clear prompt delimiters separating system instructions from analyzed code.
   - No model tool/filesystem access beyond reading the target; note the
     deep-scan "tool-use escalation loop" widens this surface.
   - Human-in-the-loop for anything gating.

**What hashes cannot do:** they prove you fetched the *authentic* artifact, not
that the model is free of bias/backdoor (that is publisher trust — Cisco/Meta),
and they offer zero protection against prompt injection (#4). Net posture:
cryptographic verification for the supply chain (#1–#3) **plus** an advisory,
strictly-validated, least-privilege design for the LLM itself (#4).

## Alternatives Evaluated

Deep research (2025–2026) into open-source, **locally-runnable** (no mandatory
egress), CLI-driven AI-SAST / AI-triage tools. Commercial/cloud options
(Semgrep Assistant, Snyk DeepCode AI, Checkmarx AI, Gecko, Endor, Xygeni) were
excluded as poor community-plugin fits (closed, cloud, egress).

| Tool | License | Role | Local model? | Languages | SARIF | ASH-fit notes |
|------|---------|------|--------------|-----------|-------|---------------|
| **ai-deep-sast** (Cisco) | Apache-2.0 (code) + Llama-3.1 (model) | Detect (semgrep+tree-sitter) + LLM triage | **Yes** (Foundation-Sec-8B) | ~16 | No (custom JSON) | Strongest **detection+triage** local fit; permissive-ish; OWASP/ASVS; needs JSON→SARIF + model provisioning. |
| **Vulnhuntr** (Protect AI) | **AGPL-3.0** ⚠️ | Deep zero-shot vuln discovery (data-flow call chains) | Yes (Ollama / OpenAI / Anthropic) | **Python only** | No | Excellent at complex multi-step vulns (LFI/AFO/RCE/XSS/SQLI/SSRF/IDOR), but **AGPL-3.0 blocks bundling** into Apache-2.0 ASH; narrow language scope; usable only as an external, separately-installed tool. |
| **SastAI** (Red Hat + NVIDIA) | Open source (Red Hat) | **Triage layer over existing SAST output** (agentic, RAG + semantic code search) | Likely (verify) | Language-agnostic (triages findings) | Verify | **Best conceptual match for the Phase-2 cross-cutting triage layer** — it triages existing SAST findings rather than detecting. Evaluate maturity/license/local-model support, and adopt-vs-build-ASH-native. |

Excluded as off-target: NVIDIA garak, agentic_security, llm-guard, SAP STARS
(these test/secure *LLMs themselves*, not code SAST), and generic Ollama agent
frameworks (not security tools).

**Takeaways:**

- For a **detection scanner** plugin, **ai-deep-sast remains the best
  open-source local candidate** — Vulnhuntr's AGPL-3.0 is a redistribution
  blocker and it is Python-only.
- For the **Phase-2 cross-cutting triage layer**, **SastAI is the closest
  existing analogue** and should be evaluated head-to-head against
  "build ASH-native (seeded by `ai-deep-sast`'s Apache-2.0 triager +
  Foundation-Sec-8B)."
- Vulnhuntr is worth keeping in view as an *optional, externally-installed*
  deep-vuln-discovery plugin for Python projects (check-only provisioning, no
  bundling) — if its AGPL posture is acceptable for an opt-in external tool.

(Web-research content was rephrased/summarized for licensing compliance; sources
listed in References.)

## References

- Reference implementation: [`ash_ferret_plugins/`](../ash_ferret_plugins/) and its
  [`DEVELOPMENT.md`](../ash_ferret_plugins/DEVELOPMENT.md).
- ASH docs: `docs/content/docs/plugins/scanner-plugins.md`,
  `docs/content/docs/plugins/development-guide.md`,
  `docs/content/docs/plugins/plugin-best-practices.md`.
- Base contract: `automated_security_helper/base/scanner_plugin.py`;
  decorator `automated_security_helper/plugins/decorators.py`.
- Upstream tool: https://github.com/cisco-open/ai-deep-sast (Apache-2.0).
- Local model card: `fdtn-ai/Foundation-Sec-8B-Instruct` (Hugging Face); technical report https://huggingface.co/papers/2508.01059; license per the model's `NOTICE.md` (Llama 3.1 Community License + Apache 2.0).
- Alternatives researched:
  - Vulnhuntr (Protect AI), AGPL-3.0: https://github.com/protectai/vulnhuntr
  - SastAI (Red Hat + NVIDIA): https://developers.redhat.com/articles/2026/06/24/harvesting-security-logic-llm
  - Semgrep CE (already an ASH built-in): https://github.com/semgrep/semgrep
- Analysis working copy used for this document: cloned to `/tmp/ai-deep-sast-analysis`.
