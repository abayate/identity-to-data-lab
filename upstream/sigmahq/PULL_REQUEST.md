<!--
Thanks for your contribution. Please make sure to fill the contents of this template with the necessary information to ease and speed up the review process.

!!! PLEASE DO NOT DELETE ANY SECTION, COMMENT OR THE CONTENT OF THE TEMPLATE. !!!
-->

### Summary of the Pull Request

<!--
**Please note that this section is required and must be filled**
A short summary of your pull request.
-->

Adds a new AWS CloudTrail rule: **AWS IAM Policy Version With Wildcard Actions Set As Default**.

It detects `CreatePolicyVersion` with `setAsDefault: true` where the new policy document grants all actions (`"*"`) or all IAM actions (`"iam:*"`), either alone or anywhere in an action list. An identity that can create versions of a policy attached to itself can turn that policy into an administrator policy in one call, a well-known AWS privilege-escalation path (Rhino Security Labs, "CreateNewPolicyVersion"). As far as I can tell, there's currently no SigmaHQ rule for `CreatePolicyVersion`.

**Testing:** the rule comes from a detection lab where every rule is tested in CI against labeled, public attack telemetry: https://github.com/abayate/identity-to-data-lab
- Fires on all 3 events of the public Splunk attack_data dataset [T1078/aws_create_policy_version](https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques/T1078/aws_create_policy_version) (including one failed attempt by a second identity).
- No alerts on 38 benign CloudTrail events (routine IAM admin activity) from the same public data.
- Regex cases: matches `"Action": "*"`, `"Action": "iam:*"` and a wildcard later in a list (`["s3:GetObject", "*"]`); does **not** match service-wide grants (`"s3:*"`) or wildcard resources with specific actions.
- `python tests/test_rules.py` and `python tests/test_logsource.py`: OK. `sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml`: 0 errors, 0 issues (sigma-cli 3.1.0, pySigma-validators-sigmahq 0.21.0).


### Changelog

<!--
** Don't remove this comment **
You need to add one line for every changed file of the PR and prefix one of the following tags:
new:	<title>
update:	<title> - <optional comment>
fix:	<title> - <optional comment>
remove:	<title> - <optional comment>
chore: for non-detection related changes (e.g. dates/titles) and changes on workflow

e.g.
new: Brute-Force Attacks on Azure Admin Account
update: Suspicious Microsoft Office Child Process - add MSPUB.EXE
fix: Malware User Agent - remove legitimate Firefox UA
chore: workflow - update checkout version
remove: Suspicious Office Execution - deprecated in favour of 8f922766-a1d3-4b57-9966-b27de37fddd2
-->

new: AWS IAM Policy Version With Wildcard Actions Set As Default


### Example Log Event

<!--
Fill this in case of false positive fixes
-->

Not a false-positive fix; for reference, a matching event from the public dataset (trimmed):

```json
{
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreatePolicyVersion",
  "userIdentity": {"type": "IAMUser", "userName": "rhino_escalate"},
  "requestParameters": {
    "policyArn": "arn:aws:iam::111111111111:policy/rhino_escalate",
    "policyDocument": "{\n   \"Version\": \"2012-10-17\",\n   \"Statement\": [\n       {\n           \"Sid\": \"AllowEverything\",\n           \"Effect\": \"Allow\",\n           \"Action\": \"*\",\n           \"Resource\": \"*\"\n       }\n    ]\n }",
    "setAsDefault": true
  }
}
```


### Fixed Issues

<!--
Link the fixed issues here, in case your commit fixes issues with rules or code
-->

None.


### SigmaHQ Rule Creation Conventions

- If your PR adds new rules, please consider following and applying these [conventions](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/)

- [x] Followed the conventions (filename, title, 4-space indentation, hyphenated tactic tags)
