# AWS module: regenerating the CloudTrail telemetry with Stratus Red Team

The committed AWS sample logs (`data/sample-logs/cloudtrail_*.jsonl`) come from Splunk's
public attack_data repository (see `simulations/public_datasets/sources.yml`); one of
those datasets was itself produced with Stratus Red Team. To produce your **own**
CloudTrail for the same steps, run [Stratus Red Team](https://stratus-red-team.cloud/)
(an open-source adversary-emulation tool by Datadog) in a **throwaway AWS account that
you own**. Never run it in an employer's account.

## Rule ↔ Stratus technique map

| Lab rule | Stratus Red Team technique | What it does in your account |
|---|---|---|
| AWS Burst of Access-Denied API Calls by One Identity | _(none built in)_: run a scanner such as CloudSploit or Prowler with a deliberately narrow read-only policy | Many denied list / describe calls |
| AWS Access Key Created for a Different IAM User | `aws.persistence.iam-backdoor-user` | Creates an access key on an existing IAM user |
| AWS IAM Policy Version Set as Default With Wildcard Actions | _(none built in)_: reproduce with the AWS CLI `aws iam create-policy-version --set-as-default` on a test policy | New default policy version with `"Action": "*"` |
| AWS IAM Role Created Trusting Any Principal or a Whole Account | `aws.persistence.iam-create-backdoor-role` | Creates a role trusting an external account |
| AWS S3 Mass Object Download by One Identity | _(none built in)_: `aws s3 sync s3://<test-bucket> ./out` on a bucket with 100+ small objects | Many `GetObject` calls (needs S3 data events) |
| AWS EBS Snapshot Shared With Another Account or Made Public | `aws.exfiltration.ec2-share-ebs-snapshot` | Shares a snapshot with an external account id |

## Steps

1. **Prepare the account:** a fresh account, billing alarm set, a CloudTrail trail for all
   regions with management events, and S3 data events for one test bucket.
2. **Install Stratus:** see https://stratus-red-team.cloud/user-guide/getting-started/
   and authenticate the AWS CLI to the lab account.
3. **Detonate one technique at a time** and note the start / end time of each:
   ```
   stratus list --platform aws
   stratus detonate aws.persistence.iam-backdoor-user
   stratus cleanup aws.persistence.iam-backdoor-user
   ```
   Stratus creates its own prerequisites (warm-up) and removes them on cleanup.
4. **Export the events:** CloudTrail console → Event history → filter by time → download
   JSON (or query CloudTrail Lake / Athena). Convert to one event per line.
5. **Add it as a dataset:** save the file under `data/raw/`, add an entry to
   `simulations/public_datasets/sources.yml` (format `cloudtrail`, with `evidence` saying
   which technique ran when), and label with `malicious_when` on the Stratus user agent
   (`stratus-red-team_...`) or the time window you noted.
6. **Re-run:** `python -m simulations.public_datasets.generate`, then `pytest` and
   `python harness/replay.py`.
7. **Clean up:** `stratus cleanup --all`, then check the billing dashboard.

Turning on GuardDuty in the same account during step 3 gives you real findings to put in
the "actually fired?" column of the GuardDuty comparison in `docs/03-detections.md`.
