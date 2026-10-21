# CLAUDE.md — Identity-to-Data Attack Chain Detection & Response Lab

> This file is the build spec AND the repo's standing context. Claude Code reads
> `CLAUDE.md` automatically, so keep it in the repo root. Build **one phase at a
> time**, stop at each phase gate, and let the human review and commit before
> moving on. Do not build all phases in one shot.

---

## 1. What this project is

A portfolio-grade **detection & response engineering** lab that follows one
realistic attack chain end to end — from stolen identity, to the data it reaches,
to a parallel cloud path — and ships **tested detections, an automated
attack-replay harness, and an auto-triage layer** for all of it.

It is built to map directly to entry/new-grad security-engineering roles at
Meta (Detect & Respond), Google (Detection & Response), Amazon (Threat
Detection / AWS SIR), CrowdStrike, Palo Alto Unit 42, and Varonis. Each of those
teams wants the same core skill: **write a detection, prove it fires on the
attack and stays quiet on normal traffic, and automate the triage.**

## 2. Design principle that makes it buildable in a terminal

Everything runs against **synthetic telemetry committed to the repo**, not live
cloud:

- `simulations/` are **log generators** — they emit the sign-in events, M365
  audit records, and CloudTrail events an attack would produce, PLUS realistic
  **benign** traffic so false-positive rate is measurable.
- `detections/` are **Sigma rules** (portable) with **KQL equivalents** for real
  deployment later.
- `harness/` is the Python layer that replays the logs, checks which rules fired,
  auto-closes known false positives, and renders an ATT&CK coverage map.
- `docs/05-go-live.md` documents how to point the exact same rules at a real
  Entra tenant (Sentinel/Log Analytics) and AWS account. That wiring is the
  human's job, not Claude Code's.

**Hard rules:**
- NEVER use real data from any current or past employer of the human.
  Synthetic only.
- Do NOT write phishing infrastructure, credential-harvesting pages, or working
  malware. The "attacker" here only emits **log records**. For the AWS module,
  use the published open-source purple-team tool **Stratus Red Team** rather than
  hand-rolled offensive code.
- Keep Python dependencies minimal and the code readable — the human is still
  learning Python and must be able to explain every file in an interview.

## 3. Coding standards

- Python 3.11+, standard library first. Allowed deps: `pyyaml`, `pytest`.
  `pandas` only if a phase genuinely needs it; justify it first.
- Every module has a docstring explaining what it does in plain English.
- Every detection rule has a matching sample-log pair: one that MUST trigger it
  (true positive) and benign traffic that MUST NOT (false positive check).
- `pytest` is the source of truth. A phase is not done until its tests pass in CI.
- Commit after each phase with a clear message. Never force-push.

## 4. Target repo structure

```
identity-to-data-lab/
  CLAUDE.md                     # this file
  README.md                     # the showcase front page (written LAST, in Phase 6)
  requirements.txt
  .github/workflows/ci.yml      # pytest + coverage report on every push
  docs/
    01-architecture.md
    02-threat-model.md          # full ATT&CK mapping of the chain
    03-detections.md            # index of every rule + what it catches
    04-runbooks.md              # IR playbooks per detection
    05-go-live.md               # wiring to real Entra tenant + AWS account
  detections/
    entra/                      # Sigma rules: AiTM, device-code, OAuth consent, token replay
    data/                       # Sigma rules: mass download / anomalous SharePoint access
    aws/                        # Sigma rules over CloudTrail: key leak, privesc, S3 exfil
  simulations/
    entra_aitm/                 # generates malicious + benign Entra sign-in / audit logs
    data_exfil/                 # generates M365 file-access logs
    aws_keyleak/                # Stratus Red Team wrapper + sample CloudTrail output
  data/
    sample-logs/                # committed JSON/CSV telemetry the harness replays
  harness/
    replay.py                   # feeds sample logs (or triggers sims) through the rules
    evaluate.py                 # which rules fired? scores TP / FP per rule
    enrich.py                   # auto-closes known-benign FPs, adds investigation context
    coverage.py                 # renders an ATT&CK coverage map (markdown + svg)
  tests/
    test_detections.py          # each rule: fires on TP sample, silent on benign
    test_harness.py
```

## 5. Phased build plan (one phase per session; stop at each gate)

### Phase 0 — Scaffold
Create the directory tree, `git init`, `requirements.txt`, a CI stub that just
runs `pytest`, and empty doc files with headings only. No logic yet.
**Gate:** `pytest` runs green on an empty suite; tree matches section 4.

### Phase 1 — Threat model + synthetic telemetry (the backbone)
Write `docs/02-threat-model.md` mapping the full chain to MITRE ATT&CK
(T1566 phishing → T1539 steal session cookie → T1078.004 cloud accounts →
T1530 data from cloud storage, plus the AWS branch). Then build the Entra log
generator in `simulations/entra_aitm/` that emits BOTH the malicious sign-in
sequence (AiTM token theft, device-code flow, anomalous token replay from a new
IP/ASN without fresh MFA) AND a larger volume of realistic benign sign-ins.
Commit the output to `data/sample-logs/`.
**Gate:** sample logs exist, are valid JSON, and a human can read the
threat-model doc and understand the attack.

### Phase 2 — Entra identity detections
Author Sigma rules in `detections/entra/` for: AiTM token replay, device-code
phishing, suspicious OAuth consent grant, and impossible-token-reuse. Each rule
gets a KQL equivalent and a short writeup in `docs/03-detections.md`. Build the
minimal Sigma matcher inside `harness/evaluate.py` (match rule logic against the
sample-log fields directly — don't pull in a heavy backend). Write
`tests/test_detections.py` so each rule fires on its TP sample and stays silent
on benign.
**Gate:** all Entra rules pass TP + FP tests in CI.

### Phase 3 — Data-layer detections (the Varonis angle)
In `simulations/data_exfil/`, generate M365 file-access telemetry where the
stolen session mass-downloads SharePoint/OneDrive files, plus benign file
activity. Add `detections/data/` rules for mass-download and anomalous
data-access-after-risky-signin. This is the "identity → data" link that makes
the project more than another identity lab.
**Gate:** data rules pass TP + FP tests; the chain from Phase 2 sign-in to
Phase 3 download is correlated in at least one rule.

### Phase 4 — AWS module
Wrap **Stratus Red Team** in `simulations/aws_keyleak/` for the key-leak →
privilege-escalation → S3-exfil path, and commit sample CloudTrail output it
produces (document the command to regenerate against a real account).
Add `detections/aws/` Sigma rules over CloudTrail. In `docs/03-detections.md`,
build the **GuardDuty-vs-custom comparison table**: for each attack step, what a
managed control like GuardDuty would flag vs. what your own rule catches. (Run
against sample GuardDuty findings; live GuardDuty is a go-live step.)
**Gate:** AWS rules pass tests; comparison table is filled in with real reasoning.

### Phase 5 — Automation harness (the Meta / Amazon differentiator)
Build out `harness/replay.py` (re-runs every simulation + replays all sample logs
through all rules on demand), `harness/enrich.py` (auto-closes a defined set of
known-benign false positives and attaches investigation context to real hits),
and `harness/coverage.py` (emits an ATT&CK coverage map as markdown + svg).
Wire `replay.py` into CI so every push reports detections fired and FP rate.
**This is the phase the human should build WITH Claude Code as tutor, not on
autopilot — see section 6.**
**Gate:** `python harness/replay.py` prints a per-rule TP/FP summary and writes
a coverage map; CI shows the summary on each push.

### Phase 6 — Runbooks, docs, and the showcase README
Write one IR runbook per detection in `docs/04-runbooks.md` (triage steps,
containment, what to pull). Write `docs/05-go-live.md` (point rules at real
Entra via Sentinel + real AWS). Then write `README.md` LAST: the front page a
recruiter sees — one-paragraph pitch, architecture diagram, the coverage map, a
results table (rules, TP rate, FP rate), and a short "how to run it" section.
Add a coverage/CI badge.
**Gate:** a stranger can clone, run `pytest` + `python harness/replay.py`, and
understand the whole project from the README alone.

### Phase 7 — Upstream contribution
Take the single strongest rule, reformat it to SigmaHQ's contribution spec, and
open a pull request to SigmaHQ (or Elastic detection-rules). A merged PR =
external validation, which beats another self-owned repo for CrowdStrike/Meta.
**Gate:** PR opened with a clear description linking back to this lab.

## 6. How the human should drive this (important)

- Work phase by phase. After each phase, review the diff, run the tests
  yourself, and commit. Do not let seven phases land as one black box.
- For **Phase 5 specifically**, don't accept generated code you can't read line
  by line. Ask Claude Code to explain each function and to let you write the
  first draft of the FP-auto-close logic yourself. Interviewers at these
  companies will probe the automation layer first; if you can't explain it, it
  works against you.
- Use plan mode at the start of each phase so you see the approach before files
  change.

## 7. Kickoff instruction (what to tell Claude Code first)

> "Read CLAUDE.md. Confirm the Phase 0 plan back to me in a few bullet points,
> then build Phase 0 only and stop at its gate."
