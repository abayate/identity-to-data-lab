# Replication Guide: Identity-to-Data Detection Lab

The step-by-step record of how this project was built, so you can rebuild it from an
empty folder, extend it, or explain every step in an interview.

The "What you should see" blocks are **real output captured while building**, so treat
them as your screenshots: if your output matches, the step worked.

---

## 0. Where the project stands

| Phase | What | Status |
|---|---|---|
| 0 | Repo scaffold, CI, doc skeletons | ✅ Done |
| 1 | Labeled sample logs from public attack datasets | ✅ Done: 1,611 malicious + 59 benign events |
| 2 | Entra identity detections (3 rules) | ✅ Done |
| 3 | Data-layer detections (4 rules), identity → data correlation | ✅ Done |
| 4 | AWS CloudTrail detections (6 rules), GuardDuty comparison | ✅ Done |
| 5 | Replay harness, auto-triage, alert queue, ATT&CK map, CI summary | ✅ Done |
| 6 | README, docs | ✅ README, architecture, detections, go-live. **Open:** runbooks (`04-runbooks.md`) and threat model (`02-threat-model.md`), written by you |
| 7 | Upstream PR to SigmaHQ | **Open:** needs your GitHub account |

Current result: **198 tests pass**, and 1,563 of 1,611 malicious events (97%) are caught by at least one rule.

---

## 1. Prerequisites (one-time)

1. **Python 3.11+**: `python --version` (built with 3.14 locally; CI uses 3.12).
2. **Git**: `git --version`.
3. **GitHub CLI** (optional, for creating the repo from the terminal): `gh --version`, then `gh auth login`.
4. A terminal: PowerShell, Git Bash, or macOS / Linux shell.

---

## 2. Run the finished project (5 minutes)

```bash
git clone https://github.com/abayate/identity-to-data-lab.git
cd identity-to-data-lab
python -m venv .venv
.venv\Scripts\activate             # Windows PowerShell
# source .venv/Scripts/activate    # Git Bash on Windows
# source .venv/bin/activate        # macOS / Linux
pip install -r requirements.txt
pytest -q
```

**What you should see:**
```
198 passed in 2.27s
```

```bash
python harness/replay.py
```

**What you should see (first lines):**
```
Loaded 1670 log events and 13 rules.

| Rule | Events | Hits | TP | FP | Auto-closed | FP rate | FP rate after triage |
|---|---|---|---|---|---|---|---|
| AWS Burst of Access-Denied API Calls by One Identity | 1333 | 2 | 2 | 0 | 0 | 0.0% | 0.0% |
| AWS Access Key Created for a Different IAM User | 1333 | 56 | 28 | 28 | 23 | 73.7% | 13.2% |
| AWS EBS Snapshot Shared With Another Account or Made Public | 1333 | 6 | 6 | 0 | 0 | 0.0% | 0.0% |
| AWS IAM Policy Version Set as Default With Wildcard Actions | 1333 | 3 | 3 | 0 | 0 | 0.0% | 0.0% |
| AWS IAM Role Created Trusting Any Principal or a Whole Account | 1333 | 2 | 2 | 0 | 0 | 0.0% | 0.0% |
| AWS S3 Mass Object Download by One Identity | 1333 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| Data Access Within One Hour of a Multi-IP Entra Session | 332 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| M365 Mass File Access or Download by One User | 289 | 4 | 4 | 0 | 0 | 0.0% | 0.0% |
| M365 File Download With Rclone User Agent | 289 | 58 | 58 | 0 | 0 | 0.0% | 0.0% |
| M365 Search for Credential or Payroll Terms | 289 | 12 | 12 | 0 | 0 | 0.0% | 0.0% |
| Entra ID Sign-In Using Device Code Flow | 43 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| Entra ID User Consent Granted to an Application | 5 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| Entra ID User Session Active From Multiple IPs Within One Hour | 43 | 3 | 3 | 0 | 0 | 0.0% | 0.0% |

**Malicious events caught by at least one rule:** 1563 / 1611
```

Then open `reports/`: `results.md` (this table), `alerts.md` (the analyst queue),
`coverage.md` and `coverage.svg` (the ATT&CK map).

---

## 3. Rebuild it from scratch, phase by phase

### Phase 0: scaffold

1. Create the folders: `detections/{entra,data,aws}`, `simulations/{public_datasets,aws_keyleak,entra_aitm,data_exfil}`,
   `data/{raw,sample-logs}`, `harness/`, `tests/`, `docs/`, `.github/workflows/`.
2. `requirements.txt`: `pyyaml>=6.0` and `pytest>=8.0`. Those are the only dependencies.
3. `pyproject.toml`: `[tool.pytest.ini_options]` with `pythonpath = ["."]` (so tests can
   `import harness`) and `testpaths = ["tests"]`.
4. `.gitignore`: `__pycache__/`, `.venv/`, `.pytest_cache/`, `.env`, `*.log`, **plus**
   `!data/raw/**/*.log` (the raw datasets are `.log` files and must be committed).
5. `.gitattributes`: `data/sample-logs/** text eol=lf` and `data/raw/** -text`, so generated
   logs are byte-identical on Windows and Linux.
6. `.github/workflows/ci.yml`: checkout, Python 3.12, `pip install -r requirements.txt`,
   `pytest -v`, `python harness/replay.py`.
7. A smoke test in `tests/test_harness.py`. An empty pytest run exits with code 5, which CI treats as a failure.

### Phase 1: real attack data, labeled

**Idea:** instead of inventing attack logs, use Splunk's
[attack_data](https://github.com/splunk/attack_data) (Apache-2.0). It holds real
telemetry captured while their team ran Evilginx, TokenTactics, rclone, Atomic Red Team,
Stratus Red Team and more in test tenants.

1. **Pick datasets.** Browse `datasets/attack_techniques/<TECHNIQUE>/` and read each
   dataset's `.yml` description. This lab uses 12 (see `simulations/public_datasets/sources.yml`).
2. **Write `sources.yml`.** For each dataset: `name`, `technique`, `scenario`, `path`,
   `metadata`, `format` (`azure_monitor`, `o365_management`, `mixed`, or `cloudtrail`), and labeling:
   - `default_label`: what an event is unless a rule below says otherwise
   - `malicious_when` / `benign_when` / `exclude_when`: Sigma-style selections on the **raw** event
   - `evidence`: a paragraph citing the dataset's description
   
   **Golden rule:** label from *who / where* the attack came from (attacker IP, attacker
   account, documented test user), **never** from the fields your rules will test.
3. **`fetch.py`** downloads each file. The repo uses Git LFS, so download from
   `media.githubusercontent.com` (real file), not `raw.githubusercontent.com` (pointer stub).
4. **`generate.py`** labels each event and converts it:
   - Azure Monitor sign-ins: flatten `properties.ipAddress` → `IPAddress` and so on (Sentinel's `SigninLogs` columns)
   - Azure audit: map to `AuditLogs` columns
   - M365 and CloudTrail: keep native field names, add `TimeGenerated`
   - write `data/sample-logs/<type>_<dataset>.jsonl` + a README of counts
5. **`schemas.py` + `tests/test_sample_logs.py`:** required vs optional fields per log type.

```bash
python -m simulations.public_datasets.fetch      # once; needs internet
python -m simulations.public_datasets.generate   # any time; offline
```

**What you should see (generate):**
```
aitm_session_cookie_replay: 22 malicious, 0 benign, 0 excluded, 0 unreadable
aitm_session_cookie_replay_m365: 9 malicious, 0 benign, 0 excluded, 0 unreadable
device_code_phishing: 4 malicious, 8 benign, 4 excluded, 0 unreadable
oauth_consent_grant: 9 malicious, 1 benign, 0 excluded, 0 unreadable
sharepoint_mass_download: 233 malicious, 12 benign, 0 excluded, 1 unreadable
sharepoint_sensitive_search: 39 malicious, 0 benign, 0 excluded, 0 unreadable
aws_leaked_key_discovery: 1150 malicious, 0 benign, 0 excluded, 0 unreadable
aws_create_access_key_for_other_user: 31 malicious, 38 benign, 6 excluded, 0 unreadable
aws_policy_version_privesc: 3 malicious, 0 benign, 0 excluded, 0 unreadable
aws_role_external_trust: 2 malicious, 0 benign, 0 excluded, 0 unreadable
aws_s3_mass_getobject: 100 malicious, 0 benign, 0 excluded, 0 unreadable
aws_ebs_snapshot_share: 9 malicious, 0 benign, 0 excluded, 0 unreadable
```

### Phases 2–4: detection rules

Every rule follows the same loop. **Use it to add your own.**

1. **Look at the data first.** Print the malicious and benign events side by side and find
   a field difference that makes sense to a defender (not one that just happens to differ).
2. **Write the Sigma file** in `detections/<area>/`:
   ```yaml
   title: <what it detects>
   id: <python -c "import uuid; print(uuid.uuid4())">
   status: experimental
   description: <why this behavior means attack>
   references: [<docs>, <dataset link>]
   author: identity-to-data-lab
   date: 2026-10-21
   tags: [attack.<tactic>, attack.tXXXX]
   logsource: {product: <azure|m365|aws>, service: <signinlogs|auditlogs|m365|cloudtrail>}
   detection:
     selection:
       FieldName: value
     condition: selection
   falsepositives: [<what legit activity trips it, and how to tune>]
   level: medium
   ```
   For counting or "same user, multiple X" logic, add a second YAML document with a
   `correlation:` block (see `detections/entra/entra_user_signin_multiple_ips.yml`). For
   "A and B happened to the same user", use `type: temporal` with `aliases`
   (see `detections/data/identity_to_data_access_after_multi_ip_session.yml`).
3. **Register the expectation** in `tests/test_detections.py` → `EXPECTED_SCENARIOS`
   (which `lab_scenario` the rule must catch). The rule itself never knows.
4. **Document it** in `docs/03-detections.md` under `### <exact rule title>` with a
   ` ```kql ` block. A test fails without it.
5. **Run** `pytest -q`, then `python harness/replay.py`.
6. **If it's noisy:** look at *who* the false positives are. If they're an approved,
   documented workflow, add an entry to `harness/known_benign.yml` **with a reason**.
   Never loosen the rule just to make a number look better. If some FPs must stay open,
   record the allowance in `ALLOWED_OPEN_FALSE_POSITIVES` with a comment.

### Phase 5: harness

| File | Job |
|---|---|
| `harness/evaluate.py` | Sigma matcher: selections, modifiers (`contains`, `re`, `fieldref`…), conditions, correlations (`event_count`, `value_count`, `temporal`), aliases, lists inside events |
| `harness/enrich.py` | Auto-close alerts matching `known_benign.yml`; attach "new IP / ASN / country for this user" context |
| `harness/coverage.py` | ATT&CK map: tested / untested / gap |
| `harness/replay.py` | Run everything, write `reports/`, post to the GitHub Actions summary |

### Phase 6: docs

README (front page), `01-architecture.md`, `03-detections.md`, `05-go-live.md`,
`interview-prep.md`, and this guide. Still to write: `04-runbooks.md` and `02-threat-model.md` (section 6).

---

## 4. See the results

| Where | How |
|---|---|
| Terminal | `pytest -v`, `python harness/replay.py` |
| `reports/` | `results.md`, `alerts.md`, `coverage.md`, `coverage.svg` (committed; GitHub renders them) |
| GitHub Actions | Repo → **Actions** → a run → **Summary** shows the replay and coverage tables |
| README | Badges, coverage map, results, interactive diagrams and expandable sections |

---

## 5. Problems hit while building, and the fixes

1. **Empty pytest suite fails CI** (exit code 5). Fix: a real smoke test.
2. **CRLF warnings on Windows** are harmless, but generated files must be LF. Fix:
   `.gitattributes` + `newline="\n"` when writing.
3. **`*.log` in `.gitignore` hid the raw datasets.** Fix: `!data/raw/**/*.log`.
4. **Git LFS pointer stubs** instead of data. Fix: download from `media.githubusercontent.com`;
   `fetch.py` refuses to save a stub.
5. **Real data broke the schema:** service-principal sign-ins have no user, timestamps came
   in three formats (one with 7 fractional digits), and one published line was truncated.
   Fix: required vs optional fields, a timestamp normalizer, skip-and-count bad lines.
6. **Each file mixes attack and normal activity.** Fix: per-event labels with evidence, and
   *exclude* events that can't be attributed instead of guessing.
7. **A test was wrong, not the rule:** "54 minutes later" is inside a 1-hour window.
   Check which side is wrong before changing code.
8. **Quadratic slowdown:** 1,150 CloudTrail events took the suite from about 1 second to 42. Fix: a
   two-pointer sliding window and ID sets (back to about 2 seconds).
9. **One noisy rule (73.7% FP) on real admin activity.** Fix: one documented known-benign
   entry (→ 13.2%), plus tests that it never hides an attack.

---

## 6. What's left

1. **Runbooks (`docs/04-runbooks.md`):** for each rule, write: how to tell if it's real
   (triage questions), what else to look at (scope), the smallest action that stops the
   attacker (containment), and what evidence to keep. Start from each rule's
   "Tuning" notes in `03-detections.md`.
2. **Threat model (`docs/02-threat-model.md`):** answer the questions in
   `docs/interview-prep.md` → Phase 1 → "Exercise" for each dataset in `sources.yml`.
3. **A bigger benign baseline:** export a week of normal activity from your own test tenant
   (`05-go-live.md`), add it as a dataset with `default_label: benign`, and see which rules get noisy.
4. **Phase 7, the SigmaHQ PR:** fork https://github.com/SigmaHQ/sigma, read its
   `CONTRIBUTING.md`, adapt the strongest rule (the CreateAccessKey `fieldref` rule or the
   device-code rule) to their naming and field conventions, run their validation, and open a PR
   that links back to this repo.
5. **Live validation:** run Stratus Red Team in a throwaway AWS account
   (`simulations/aws_keyleak/README.md`) with GuardDuty on, and fill in the "actually fired?"
   column of the GuardDuty comparison.

---

## 7. Command cheat sheet

| Task | Command |
|---|---|
| Activate venv (PowerShell) | `.venv\Scripts\activate` |
| Install deps | `pip install -r requirements.txt` |
| Run tests | `pytest -q` (or `-v` for every test name) |
| Run the harness | `python harness/replay.py` |
| Rebuild logs, then run | `python harness/replay.py --regenerate` |
| Download raw data again | `python -m simulations.public_datasets.fetch` |
| New rule id | `python -c "import uuid; print(uuid.uuid4())"` |
| Commit | `git add -A` then `git commit -m "..."` |
| Push | `git push` |
