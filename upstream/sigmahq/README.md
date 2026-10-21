# Upstream contribution: SigmaHQ

> **Status:** submitted as [SigmaHQ/sigma#6501](https://github.com/SigmaHQ/sigma/pull/6501)
> on 2026-10-21. It's waiting for maintainer review; SigmaHQ's own validation workflows are
> waiting for maintainer approval, as they do for all first-time contributors.

This folder holds lab rules reformatted to [SigmaHQ](https://github.com/SigmaHQ/sigma)'s
conventions, ready to submit as a pull request. The folder layout mirrors theirs, so a file
copies straight into a fork at the same path.

## The candidate

[`rules/cloud/aws/cloudtrail/aws_iam_policy_version_wildcard_actions_set_default.yml`](rules/cloud/aws/cloudtrail/aws_iam_policy_version_wildcard_actions_set_default.yml)
is derived from the lab rule
[`detections/aws/aws_policy_version_grants_wildcard.yml`](../../detections/aws/aws_policy_version_grants_wildcard.yml).

**Why this one:**
- **It isn't a duplicate.** SigmaHQ (checked at commit `05d1031`, 2026-10-21) has no
  CloudTrail rule for `CreatePolicyVersion`. Our other strong rules already have SigmaHQ
  equivalents: device-code sign-in (`azure_app_device_code_authentication.yml`), user consent
  (`azure_app_end_user_consent.yml`), key for another user (`aws_iam_backdoor_users_keys.yml`),
  and snapshot exfiltration (`aws_snapshot_backup_exfiltration.yml`).
- **It's high-signal and simple:** one event, no correlation, and it reads *what the policy
  grants*, which GuardDuty's anomaly findings don't (see `docs/03-detections.md`).
- **It's tested on real attack data:** the public Splunk attack_data dataset for this technique.

## How it was validated

| Check | Command (run inside a SigmaHQ clone) | Result |
|---|---|---|
| SigmaHQ rule tests | `python tests/test_rules.py` | ✅ 11 tests OK |
| SigmaHQ logsource tests | `python tests/test_logsource.py` | ✅ 3 tests OK |
| sigma-cli with SigmaHQ's validators | `sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml <rule>` | ✅ 0 errors, 0 issues |
| Same behaviour as the lab rule on real data | `pytest tests/test_upstream.py` (this repo) | ✅ identical alerts |
| Regex edge cases (wildcard later in a list, service-only wildcards) | `pytest -k policy_wildcard_regex` (this repo) | ✅ 6 cases |

Tool versions: sigma-cli 3.1.0, pySigma 1.5.1, pySigma-validators-sigmahq 0.21.0.
(SigmaHQ's `check-baseline-local.sh` replays Windows EVTX baselines and doesn't apply to CloudTrail rules.)

## Submitting it (from your GitHub account)

```bash
gh repo fork SigmaHQ/sigma --clone=false
git -c core.longpaths=true clone --depth 1 https://github.com/<you>/sigma.git
cd sigma
git checkout -b aws-iam-policy-version-wildcard
cp <this repo>/upstream/sigmahq/rules/cloud/aws/cloudtrail/aws_iam_policy_version_wildcard_actions_set_default.yml \
   rules/cloud/aws/cloudtrail/
python tests/test_rules.py && python tests/test_logsource.py
git add rules/cloud/aws/cloudtrail/aws_iam_policy_version_wildcard_actions_set_default.yml
git commit -m "new: AWS IAM Policy Version With Wildcard Actions Set As Default"
git push -u origin aws-iam-policy-version-wildcard
gh pr create --repo SigmaHQ/sigma --title "new: AWS IAM Policy Version With Wildcard Actions Set As Default" --body-file <this repo>/upstream/sigmahq/PULL_REQUEST.md
```

The rule credits **Anthony Bayate Jr.** as author. Before submitting, check SigmaHQ's latest
merged PRs for any change in conventions.
