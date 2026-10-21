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
