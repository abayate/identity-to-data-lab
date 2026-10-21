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

---

## Phase 1 — Telemetry from public attack datasets

### The 30-second version

> "Instead of making up attack logs, I used Splunk's open attack_data repo. It has
> real Entra and M365 telemetry captured while their research team ran tools like
> Evilginx and TokenTactics in a test tenant. I wrote a converter that flattens
> Azure's raw export format into Sentinel's column names and labels every event
> malicious or benign from documented evidence. A test fails if the committed logs
> ever drift from what the converter produces."

### Walk me through the pipeline

1. **`sources.yml`** lists each dataset: its URL, the ATT&CK technique, and labeling
   rules with a written `evidence` paragraph.
2. **`fetch.py`** downloads the raw files once. They're committed, so CI never needs
   the internet. The upstream repo uses Git LFS, so `fetch.py` refuses to save an
   LFS "pointer stub" by mistake.
3. **`generate.py`** labels each raw event, converts it to Sentinel's schema, and
   writes `data/sample-logs/`, plus a README of counts per dataset.

### Why label each event instead of each file?

Each file mixes the attack with ordinary activity. In the device-code dataset, the
victim browses the portal normally from one address while the device-login that
hands over the token comes from another. Labeling the whole file malicious would
make normal behavior look like an attack, and your FP numbers would be meaningless.

### What's the circular-labeling trap?

If I labeled "malicious = AuthenticationProtocol is deviceCode" and then wrote a rule
"fire when AuthenticationProtocol is deviceCode", the rule would score 100% by
definition. So labels come from the dataset's documentation (which IP / account the
attack used), never from the fields the rules test.

### Why "exclude" some events?

Four service-principal sign-ins in the device-code file aren't described by the
dataset author. Guessing a label would put made-up ground truth into the scoring.
Dropping them, and counting how many were dropped, is the honest choice.

### What surprised you about real data? (good question to have an answer for)

- Timestamps came in three formats, including 7 fractional digits that Python can't parse.
- Required fields weren't always there. Service-principal sign-ins have no user, so
  the schema split into required and optional fields.
- One published line was truncated mid-JSON. The converter skips and counts it
  instead of crashing.
- The raw export nests fields under `properties` in camelCase, but Sentinel's
  `SigninLogs` uses flat PascalCase columns, so rules written against one won't
  match the other.

### The limitation to admit up front

Only **21 benign events** survive labeling. That's enough to prove the pipeline,
but not to claim a meaningful false-positive rate. The fix is a benign baseline
exported from your own test tenant (see `docs/05-go-live.md`). Saying this before
an interviewer asks is a strength.

### Exercise: write the threat model yourself (`docs/02-threat-model.md`)

Open `simulations/public_datasets/sources.yml` and, for each dataset, answer in
your own words:
1. What does the attacker have before this step, and what do they have after?
2. Which ATT&CK technique is it, and why that one and not a neighbor?
3. Which log table records it, and which two or three fields give it away?
4. What would a defender lose if this step went undetected?

### Practice questions

1. Why commit the raw data *and* the converted data?
2. What does `test_committed_sample_logs_are_up_to_date` protect against?
3. Why does `.gitattributes` force LF line endings for `data/sample-logs/`?
4. Why are only 21 benign events a problem, and how would you fix it?

---

## Phase 2 — Entra identity detections

### The 30-second version

> "I wrote three Sigma rules for the identity stage: device-code sign-ins, OAuth consent
> grants, and one user signing in from multiple IPs within an hour, which is how AiTM
> cookie replay shows up. The last one is a Sigma correlation rule, so I extended my
> matcher to group events and count distinct values in a sliding window. Each rule
> fires on its public-dataset attack and raises no all-benign alerts, and the tests
> also stop any rule from reading the answer key."

### Walk through each rule in one sentence

| Rule | One-sentence logic | Biggest FP source |
|---|---|---|
| Device code sign-in | `AuthenticationProtocol == deviceCode` | Admins using CLIs, meeting-room devices |
| OAuth consent granted | Audit `Consent to application`, success | Users approving real third-party apps |
| Multiple IPs in 1h | ≥2 distinct IPs per user in a sliding hour | Roaming users, VPN, IPv4 + IPv6 |

### What's a correlation rule and why did you need one?

A normal rule looks at one event at a time. Cookie replay isn't visible in any single
event, because each sign-in looks fine on its own. It only shows when you compare the
same user's sign-ins: two IPs at once. Sigma v2 handles this with a second YAML document
(`correlation:`) that groups the base rule's matches (`group-by: UserPrincipalName`) and
counts distinct values (`value_count` of `IPAddress`) inside a `timespan`.

### Why score alerts instead of events?

An analyst gets alerts, not events. The multi-IP alert for the phished device-code user
includes their normal sign-ins too, but the alert itself is correct. Counting those 8
normal events as 8 false positives would punish the rule for being right. So an alert is
a TP if it holds any malicious event, and an FP if it's all benign.

### Why did T1566 and T1539 stay gaps?

The phishing email (T1566) is in mail-flow logs, not sign-in logs. The cookie theft
(T1539) happens on the attacker's proxy, which we never see. Sign-in logs only show the
**use** of the stolen cookie (T1550.004). An honest coverage map shows what each log
source can and can't see.

### How do the tests stop a rule from cheating?

`test_rule_does_not_read_the_answer_key` fails if a rule mentions any `lab_` field, or
any literal value `sources.yml` used to decide labels (like the attacker IP `4.4.4.4`).
A rule matching on the labeling IP would score 100% and detect nothing in real life.

### Why is there a test that *expects* a false positive?

`test_multi_ip_rule_known_false_positive_roaming_user` builds a normal user who moves
from office Wi-Fi to a hotspot, and asserts the rule **does** fire. The public data has
no roaming users, so without this test the 0% FP number would hide a real weakness.
Writing limitations down as tests keeps them from being forgotten.

### Practice questions

1. Why does the multi-IP rule's base rule exclude events with no `UserPrincipalName`?
2. The KQL uses `bin(TimeGenerated, 1h)`, but the matcher uses a sliding window. Give a case where they disagree.
3. How would the multi-IP rule change if you had `SessionId`?
4. Device-code phishing gets past MFA. Why? What control actually stops it?
5. A consent-grant victim resets their password. Is the attacker locked out? Why or why not?

---

## Phase 3 — Data-layer detections and the identity → data link

### The 30-second version

> "Identity rules tell you a session might be stolen. Data rules tell you what it took.
> I added four M365 rules: mass file access, rclone downloads, searches for credential
> and payroll terms, and a cross-source temporal correlation that fires only when a
> user flagged for a multi-IP session also reads data within the hour. Together, all
> the rules catch 274 of 316 malicious events, and every rule stays quiet on the
> benign events we have."

### What makes the identity → data rule different?

Three things, each a Sigma v2 feature I had to add to the matcher:
1. **Temporal correlation:** "rule A and rule B both fired for the same user within
   an hour", in either order.
2. **Chaining:** rule A is itself a correlation (the multi-IP rule), so it's a
   correlation of a correlation.
3. **Aliases across log sources:** the user is `UserPrincipalName` in sign-ins and `UserId`
   in M365 audit. `aliases` maps both to one `user` key (compared lowercase).

### Why require both halves?

Precision. The multi-IP rule alone is noisy (roaming users), and data access alone is
just people doing their jobs. The intersection is rare and serious. The tests prove it
won't fire with only one half, or when the two are more than an hour apart.

### Why count events with a threshold instead of a per-user baseline?

Simplicity and explainability: "more than 20 files in 10 minutes" is easy to defend and
to test. The trade-off: a power user can exceed it legitimately (new-laptop sync, which
a test documents). Production would compare each user to their own history.

### Why keep a rule (rclone) that an attacker can trivially evade?

Defense in depth. It's cheap, it's high-confidence when it fires, and many real crews
don't bother changing the user agent. The volume rule catches the attacker who does.
Saying "here's how I'd evade my own rule, and here's what still catches it" is a strong
interview answer.

### A bug I caught in my own test (good story)

My first "access too late" test put the mailbox read 54 minutes after the first
sign-in and expected no alert. The rule fired, and it was right: 54 minutes is inside
a one-hour window. The test was wrong, not the rule. When a test fails, check which
side is wrong before changing code.

### Practice questions

1. Walk me through how the temporal rule decides two events belong to the same user.
2. Why did the SharePoint exfil dataset never trigger the identity → data rule?
3. Your mass-download rule produced 4 alerts but rclone produced 58. Why, and does it matter?
4. How would an attacker beat each data rule? What would still catch them?
5. Why is `MailItemsAccessed` in the data-access base rule? What licensing does it need in real M365?

---

## Phase 4 — AWS: leaked key → escalation → exfiltration, and GuardDuty vs custom

### The 30-second version

> "For the AWS branch I used six public CloudTrail datasets covering discovery with a
> stolen key, two privilege-escalation paths, a backdoor role, S3 mass download, and
> snapshot sharing, which was partly produced with Stratus Red Team. Six rules catch every
> step. One was noisy on real admin activity, 73.7% FP, so I added one documented
> known-benign entry that cut what analysts see to 13.2% without hiding a single attack,
> and CI enforces both of those facts. I also compared each step with what GuardDuty would
> flag: GuardDuty wins on threat intel and baselining, custom rules win when the content
> of the API call is the signal."

### The best story in the project: the noisy rule

"Create an access key for a different user" fired 56 times: 28 attacks and 28 admins doing
their jobs. I didn't loosen the rule. I looked at *who* the false positives were: 23 came
from federated admins in the console through an Okta role, which is an approved workflow.
One known-benign entry with a written reason closed exactly those. The other 5 stayed open
on purpose, because a stolen admin key would look like them. Then I wrote two tests: one
caps open FPs at 5, and one fails if suppression ever closes a true positive.

### What's `fieldref` and why did you need it?

Normal Sigma compares a field to a constant. "Key created for someone other than the
caller" compares two fields of the same event: `requestParameters.userName` vs
`userIdentity.userName`. Sigma v2 added the `|fieldref` modifier for that, so I added it
to the matcher. Gotcha: federated (AssumedRole) callers have no `userName`, so their keys
always look like "for someone else", which is where most of the noise came from.

### Where does Sigma fall short, and what did you do?

The role-trust rule wants "trusted account ≠ this account", but the account is inside a
JSON string and the other value is a separate field. Sigma can't express that. The KQL
version can (`extract()` then compare to `RecipientAccountId`), so the doc gives both and
says which is stricter. Knowing a tool's limits is part of the job.

### A performance bug I hit

Adding 1,150 CloudTrail events made the suite go from about 1 second to 42. The sliding window
rescanned every event for every window start, and removed duplicates with a list scan:
quadratic twice over. A two-pointer window plus an ID set brought it back to about 2 seconds.
Lesson: correlation over big log volumes is where naive code hurts first.

### Practice questions

1. Why is the key-leak step a gap in your coverage map? What would cover it?
2. Your S3 rule is "blind by default". Why, and what does turning it on cost?
3. Which GuardDuty finding would you trust more than your own rule, and why?
4. What's the risk of the known-benign entry you wrote? How would an attacker abuse it?
5. Why keep a failed `CreatePolicyVersion` attempt as an alert?

---

## Phase 5 — Finishing the automation harness

### What does an analyst actually get?

`reports/alerts.md`, the alert queue. Each open alert lists the context `enrich.py`
attached (user, IPs and countries in the alert, and whether each is **new for this user**)
plus the first few events. Auto-closed alerts are grouped by the known-benign entry that
closed them, with its written reason. The answer key is deliberately left out, and a test
checks that, because an analyst never gets to see `lab_label`.

### What does `--regenerate` prove?

`python harness/replay.py --regenerate` rebuilds every sample log from the raw data before
replaying. Running it and then `git status` showing *no changes* proves the pipeline is
deterministic: anyone can reproduce the exact committed results.

### The automation in one breath

Raw public data → labeled sample logs (`generate.py`) → every rule over its log types
(`replay.py` + `evaluate.py`) → triage: auto-close with reasons, context for the rest
(`enrich.py`) → reports: results table, alert queue, ATT&CK map (`coverage.py`) → CI runs
all of it on every push and posts the tables to the Actions summary.

### Practice questions

1. Walk me through what happens, file by file, when you push a commit.
2. What context would you add next to `enrich.py`? (Ideas: a geo-IP / ASN reputation lookup,
   the user's group memberships, recent password resets.)
3. Why does the alert queue show at most five events per alert?
