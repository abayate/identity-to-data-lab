# Interview Prep

Plain-English notes so you can explain every part of this project out loud.
One section per phase. Read it, then try explaining each answer without looking.

---

## Phase 0 — Scaffold

### The 30-second version

> "Before writing any detection logic I set up the repo so every later piece has
> a home and gets tested automatically. Rules live in `detections/`, the code that
> generates test logs lives in `simulations/`, the logs themselves are committed to
> `data/sample-logs/`, and `harness/` is the Python that runs rules against logs and
> scores them. GitHub Actions runs `pytest` on every push, so nothing lands
> without passing tests."

### Why is the repo laid out this way?

Each folder has exactly one job, and the jobs mirror how a real detection team works:

| Folder | Job | Real-world equivalent |
|---|---|---|
| `detections/` | The rules (what to look for) | A team's detection-as-code repo |
| `simulations/` | Code that produces test logs | Purple-team / attack-emulation tooling |
| `data/sample-logs/` | The logs themselves, committed | A test fixture dataset |
| `harness/` | Runs rules over logs, scores hits | The CI pipeline that validates rules |
| `tests/` | `pytest` checks | Unit tests for detections |
| `docs/` | Threat model, runbooks, go-live | Team wiki / playbooks |

Splitting **rules** from **data** from **the code that runs them** means you can change
one without breaking the others. For example, you can swap the sample logs for real
ones later and leave the rules alone.

### Why synthetic logs instead of a real cloud tenant?

- **Reproducible:** anyone who clones the repo gets the exact same results. A live
  tenant changes every day.
- **Free and safe:** no cloud bill and no risk of touching real accounts.
- **Measurable:** you control which events are malicious, so you can actually
  calculate true-positive and false-positive rates. In real logs you rarely know
  the ground truth.
- **No real data:** nothing from any employer ever goes in this repo.

The trade-off to admit if asked: synthetic logs are only as realistic as your
understanding of the real log schema. That's why `docs/05-go-live.md` exists. It
explains how to point the same rules at a real tenant and check them there.

### Why Sigma rules?

Sigma is a vendor-neutral format for detection rules, written in YAML. You write a
rule once and it can be converted to Splunk, Microsoft Sentinel (KQL), Elastic,
and others. It's the closest thing the industry has to a standard, and SigmaHQ is
the public community repo you contribute to in Phase 7.

### What does each config file do?

- **`requirements.txt`** lists the Python packages the project needs (`pyyaml` to
  read the YAML rules, `pytest` to run tests). CI installs from it with
  `pip install -r requirements.txt`.
- **`pyproject.toml`** holds pytest settings. `pythonpath = ["."]` lets tests write
  `import harness` without installing the project as a package.
  `testpaths = ["tests"]` tells pytest where to look.
- **`.gitignore`** keeps junk out of git: `__pycache__/` (compiled Python),
  `.venv/` (your local virtual environment), `.pytest_cache/`, and `.env`
  (secrets should never be committed).
- **`.github/workflows/ci.yml`** is the GitHub Actions pipeline (see below).

### Walk me through the CI workflow

```yaml
on:
  push:
  pull_request:
```
Run on every push and every pull request.

```yaml
runs-on: ubuntu-latest
```
GitHub gives us a fresh Linux machine each run, so no leftover state.

```yaml
- uses: actions/checkout@v4        # download the repo onto that machine
- uses: actions/setup-python@v5    # install Python 3.12
- run: pip install -r requirements.txt
- run: pytest -v                   # run the tests; any failure fails the build
```

If `pytest` exits with a non-zero code, the run turns red on GitHub. That red/green
signal is the project's quality gate.

### What is a virtual environment (`.venv`) and why use one?

It's a private copy of Python with its own installed packages, just for this
project. It keeps this project's dependencies from clashing with other projects on
your machine. It's in `.gitignore` because anyone can recreate it with
`python -m venv .venv` and `pip install -r requirements.txt`.

### Why is there a test when there's no logic yet? (good gotcha question)

`pytest` exits with **code 5** when it finds zero tests, and CI treats any non-zero
exit as a failure. So an empty suite would turn the pipeline red. Instead of hiding
that with a flag, I added a real smoke test in `tests/test_harness.py` that checks:

1. Every expected folder exists.
2. Every `harness/` module can be imported and has a docstring.

`@pytest.mark.parametrize` runs the same test function once per item in a list, so
10 folders + 4 modules = 14 separate test results. If one folder goes missing,
the output tells you which one.

### Why does every module have a docstring?

The project's coding standard says every file must explain what it does in plain
English. The smoke test enforces that for the harness modules, so a missing
docstring fails the build. It's a small example of turning a rule into an
automated check instead of relying on memory.

### Why does git show "LF will be replaced by CRLF"?

Windows ends lines with CRLF and Linux/Mac use LF. Git is warning that it will
convert line endings on checkout. It's harmless, and CI runs on Linux.

### Practice questions

1. Why did you separate `simulations/` from `data/sample-logs/`?
2. What happens on GitHub when you push a commit that breaks a test?
3. What would you lose by testing against a live tenant instead of synthetic logs?
   What would you gain?
4. What does `pythonpath = ["."]` do, and what error would you see without it?
5. Why commit after each phase instead of once at the end?

---

## Phase 1 (part 1) — Log schema and sample-log tests

### The 30-second version

> "Before generating any logs I pinned down what one sign-in record looks like. The
> field names copy Microsoft's real `SigninLogs` table, so rules I write against the
> synthetic data work on a real tenant later. Every record also carries an answer
> key, `lab_label`, that says benign or malicious, which is how the harness can score
> true and false positives. A pytest file checks that every committed log file
> parses and matches that schema."

### Why copy the real Microsoft field names?

The whole point of the lab is that the rules transfer to production. If my synthetic
logs used made-up names like `user` and `ip`, every rule would need rewriting at
go-live. Using `UserPrincipalName`, `IPAddress`, `AuthenticationRequirement` and so
on means the KQL equivalents can run against Sentinel unchanged.

### What are the `lab_` fields and why can't rules use them?

`lab_label` and `lab_scenario` are the ground truth. Real logs never come with a
"this was an attacker" column. That's exactly why detection is hard. If a rule
matched on `lab_label`, it would score 100% and prove nothing. The `lab_` prefix
makes the cheat obvious in code review.

### Why JSON Lines (`.jsonl`) instead of one big JSON array?

One event per line is how most log exports and SIEM ingestion pipelines work.
You can read it line by line without loading the whole file, and a broken line
points to an exact line number in the test failure.

### Why does the test file test its own checker?

`check_record` is the code that decides whether a log is valid. If it had a bug
and accepted everything, every sample-log test would pass and mean nothing. The
`test_checker_*` tests feed it known-bad records (missing field, bad label, bad
timestamp) and confirm it complains. That's testing the test.

### Why are two tests "skipped"?

No sample logs are committed yet. `skipif` marks those tests as skipped instead of
failing, so CI stays green while the generator gets built. Once an
`entra_signins*.jsonl` file exists, they run automatically.

### Practice questions

1. What would break at go-live if the synthetic logs used invented field names?
2. Why is `AutonomousSystemNumber` useful for spotting a stolen-token replay?
3. What does `IncomingTokenType` tell you that a normal login field doesn't?
4. Why does the suite check that both `benign` and `malicious` labels appear?

---

## Phase 2 (engine) — The minimal Sigma matcher (`harness/evaluate.py`)

### The 30-second version

> "Instead of pulling in a full Sigma backend, I wrote a small matcher, about 200
> lines, that reads a rule's `detection` block and checks it directly against each
> log record. It supports selections, the common field modifiers, and the condition
> language: and/or/not, parentheses, and `1 of`/`all of`. Then `score_rule` compares
> the rule's hits against the answer key to give true positives, false positives
> and a false-positive rate."

### How does a Sigma rule get evaluated, step by step?

1. **Selections first.** Each named block under `detection:` (like `selection` or
   `filter_known_vpn`) is checked against the record and becomes True or False.
   - Fields inside one map are **AND**ed.
   - A list of values for one field is **OR**ed.
   - A list of maps is **OR**ed.
2. **Then the condition.** The `condition:` line is evaluated using those
   True/False values, e.g. `selection and not filter_known_vpn`.

### How does the condition parser work?

It's a recursive-descent parser, one small function per precedence level:
`parse_or` calls `parse_and`, which calls `parse_not`, which calls `parse_atom`.
Because `and` sits deeper than `or`, `a or b and c` is read as `a or (b and c)`,
the same as in most programming languages. Parentheses go back to the top
(`parse_or`), which is how they override precedence.

### Why write your own matcher instead of using pySigma?

- pySigma's job is converting rules into SIEM queries (KQL, SPL). It doesn't
  evaluate rules against JSON in Python. I'd still need a SIEM to run them.
- Writing it myself means I can explain exactly what "the rule fired" means.
- The trade-off: it only supports the subset of Sigma my rules use. Correlation
  rules and aggregations aren't supported, and the docstring says so.

### Why are string matches case-insensitive?

The Sigma spec says so, and real logs are inconsistent (`Alice@Contoso.com` vs
`alice@contoso.com`). A case-sensitive match is an easy way for an attacker to
slip past a rule. Regexes are the exception: they're used as written, so the rule
author controls case.

### Why doesn't `score_rule` count false negatives?

Each rule targets one step of the attack. A rule built for one step *should* stay
quiet on events from a different step, so counting those as misses would be
unfair. Whole-chain coverage, meaning did *some* rule catch each malicious event,
gets measured across all rules together in the replay harness.

### Practice questions

1. Walk me through how `selection and not filter` is evaluated for one record.
2. What does `1 of selection*` mean? When would you use it?
3. What does `null` mean as a value in a Sigma selection?
4. A rule has a 0% FP rate on your synthetic data. Why might it still be noisy in production?
5. Why does `parse_or` evaluate the right-hand side even when the left side is already True?

---

## Phase 5 (tooling) — Triage, coverage map, and replay runner

### The 30-second version

> "`replay.py` loads every log and every rule, runs each rule only against its own
> log type, and scores it. `enrich.py` then triages the hits: anything matching a
> documented known-benign pattern is auto-closed, and everything else gets context,
> like whether this IP or network is new for this user. `coverage.py` turns the rules'
> ATT&CK tags into a map that marks each technique tested, untested, or a gap. CI runs
> all of it on every push and posts the tables to the Actions summary page."

### Why does every known-benign entry need a reason?

An auto-close is a deliberate blind spot. If nobody can say why it exists, nobody
can tell when it has gone stale. The loader refuses entries without a `reason`, which
turns a team norm into an enforced check.

### What's the difference between "FP rate" and "FP rate after triage"?

FP rate is how often the raw rule fires on benign traffic. After triage, it's the FP
rate an analyst actually sees once known-benign hits are auto-closed. Reporting both
shows the rule's own precision *and* the value of the automation.

### Why "tested" vs "untested" in the coverage map?

A rule tagged with a technique proves nothing until it catches real attack telemetry.
Only "tested" techniques count as covered. Plenty of coverage maps out there just
count rules.

### Practice questions

1. Why does replay match rules to log files by `logsource` instead of running every rule on every log?
2. What's the risk of an over-broad known-benign entry? How would you catch one?
3. How does `build_context` decide an IP is "new for the user"? What's its weakness on a small dataset?
4. How does the CI summary page get the table? (Hint: `GITHUB_STEP_SUMMARY`.)
