# Alert queue

Open alerts carry the context `harness/enrich.py` attached. Auto-closed alerts
show the `known_benign.yml` entry that closed them.

## AWS Burst of Access-Denied API Calls by One Identity

2 open, 0 auto-closed.

**Open #1** (37 event(s))

- user: arn:aws:iam::731544447609:user/cloudmapper
- events_in_alert: 37
- other_events_for_user: 0
- sourceIPAddress_values: ['34.12.134.20']
- new_sourceIPAddress_for_user: True

```
2021-04-13T13:30:36.000000Z | arn:aws:iam::731544447609:user/cloudmapper | ListKeyPolicies | 34.12.134.20
2021-04-13T13:30:41.000000Z | arn:aws:iam::731544447609:user/cloudmapper | ListKeyPolicies | 34.12.134.20
2021-04-13T13:31:05.000000Z | arn:aws:iam::731544447609:user/cloudmapper | GetKeyRotationStatus | 34.12.134.20
2021-04-13T13:31:10.000000Z | arn:aws:iam::731544447609:user/cloudmapper | GetKeyRotationStatus | 34.12.134.20
2021-04-13T13:33:45.000000Z | arn:aws:iam::731544447609:user/cloudmapper | ListAccounts | 34.12.134.20
... 32 more
```

**Open #2** (1113 event(s))

- user: arn:aws:iam::731544447609:user/cloudsploit
- events_in_alert: 1113
- other_events_for_user: 0
- sourceIPAddress_values: ['34.12.134.20']
- new_sourceIPAddress_for_user: True

```
2021-04-13T11:32:51.000000Z | arn:aws:iam::731544447609:user/cloudsploit | ListCertificates | 34.12.134.20
2021-04-13T11:32:52.000000Z | arn:aws:iam::731544447609:user/cloudsploit | ListDistributions2020_05_31 | 34.12.134.20
2021-04-13T11:32:52.000000Z | arn:aws:iam::731544447609:user/cloudsploit | ListCertificates | 34.12.134.20
2021-04-13T11:32:52.000000Z | arn:aws:iam::731544447609:user/cloudsploit | DescribeTrails | 34.12.134.20
2021-04-13T11:32:52.000000Z | arn:aws:iam::731544447609:user/cloudsploit | ListCertificates | 34.12.134.20
... 1108 more
```

## AWS Access Key Created for a Different IAM User

33 open, 23 auto-closed.

**Open #1** (1 event(s))

- user: arn:aws:iam::121521347698:user/peterg
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['99.152.112.173']
- new_sourceIPAddress_for_user: False

```
2020-08-04T15:02:44.000000Z | arn:aws:iam::121521347698:user/peterg | CreateAccessKey | 99.152.112.173
```

**Open #2** (1 event(s))

- user: arn:aws:iam::121521347698:user/jose_cli
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['73.204.247.3']
- new_sourceIPAddress_for_user: False

```
2020-08-14T04:10:07.000000Z | arn:aws:iam::121521347698:user/jose_cli | CreateAccessKey | 73.204.247.3
```

**Open #3** (1 event(s))

- user: arn:aws:iam::121521347698:user/jose_cli
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['73.204.247.3']
- new_sourceIPAddress_for_user: False

```
2020-08-14T04:10:07.000000Z | arn:aws:iam::121521347698:user/jose_cli | CreateAccessKey | 73.204.247.3
```

**Open #4** (1 event(s))

- user: arn:aws:iam::121521347698:user/jzadeh_cli
- events_in_alert: 1
- other_events_for_user: 0
- sourceIPAddress_values: ['76.170.250.73']
- new_sourceIPAddress_for_user: True

```
2020-08-31T18:27:37.000000Z | arn:aws:iam::121521347698:user/jzadeh_cli | CreateAccessKey | 76.170.250.73
```

**Open #5** (1 event(s))

- user: arn:aws:iam::121521347698:user/ignacio_cli
- events_in_alert: 1
- other_events_for_user: 0
- sourceIPAddress_values: ['135.180.192.99']
- new_sourceIPAddress_for_user: True

```
2021-02-19T04:10:37.000000Z | arn:aws:iam::121521347698:user/ignacio_cli | CreateAccessKey | 135.180.192.99
```

**Open #6** (1 event(s))

- user: arn:aws:iam::121521347698:user/rhino_escalate
- events_in_alert: 1
- other_events_for_user: 3
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-22T23:28:24.000000Z | arn:aws:iam::121521347698:user/rhino_escalate | CreateAccessKey | 12.25.72.12
```

**Open #7** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-25T22:35:33.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #8** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-25T22:40:34.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #9** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T00:59:56.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #10** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T00:59:56.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #11** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:03:01.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #12** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:03:01.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #13** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:06:41.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #14** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:06:41.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #15** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:08:10.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #16** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:08:10.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #17** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:13:51.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #18** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:17:20.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #19** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:20:27.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #20** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:25:44.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #21** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:27:19.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #22** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:28:42.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #23** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:33:48.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #24** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:35:52.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #25** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:40:05.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #26** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:50:47.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #27** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T01:56:01.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #28** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-02-26T02:26:30.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #29** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-03-02T20:47:23.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #30** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-03-02T20:58:29.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #31** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-03-02T21:02:38.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #32** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-03-02T21:14:13.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

**Open #33** (1 event(s))

- user: arn:aws:iam::121521347698:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 31
- sourceIPAddress_values: ['12.25.72.12']
- new_sourceIPAddress_for_user: False

```
2021-03-02T21:18:24.000000Z | arn:aws:iam::121521347698:user/bhavin_cli | CreateAccessKey | 12.25.72.12
```

- Auto-closed x23: federated-admins-console-key-provisioning: The cloud team provisions IAM access keys for service and team accounts from the AWS console after signing in through the company IdP (Okta) into the okta_adm_role admin role. That role requires IdP MFA and is limited to the cloud team, so a key created this way is an approved admin action. Keys created any other way (CLI, long-lived IAM user keys, root) stay open for review.


## AWS EBS Snapshot Shared With Another Account or Made Public

6 open, 0 auto-closed.

**Open #1** (1 event(s))

- user: arn:aws:iam::591511666666:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 2
- sourceIPAddress_values: ['72.135.232.230']
- new_sourceIPAddress_for_user: False

```
2021-06-22T20:58:37.000000Z | arn:aws:iam::591511666666:user/bhavin_cli | ModifySnapshotAttribute | 72.135.232.230
```

**Open #2** (1 event(s))

- user: arn:aws:iam::591511666666:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 2
- sourceIPAddress_values: ['72.135.232.230']
- new_sourceIPAddress_for_user: False

```
2021-06-22T21:03:16.000000Z | arn:aws:iam::591511666666:user/bhavin_cli | ModifySnapshotAttribute | 72.135.232.230
```

**Open #3** (1 event(s))

- user: arn:aws:sts::591511666666:assumed-role/okta_adm_role/bpatel@splunk.local
- events_in_alert: 1
- other_events_for_user: 3
- sourceIPAddress_values: ['72.135.232.230']
- new_sourceIPAddress_for_user: False

```
2021-06-22T21:04:59.000000Z | arn:aws:sts::591511666666:assumed-role/okta_adm_role/bpatel@splunk.local | ModifySnapshotAttribute | 72.135.232.230
```

**Open #4** (1 event(s))

- user: arn:aws:sts::591511666666:assumed-role/okta_adm_role/bpatel@splunk.local
- events_in_alert: 1
- other_events_for_user: 3
- sourceIPAddress_values: ['72.135.232.230']
- new_sourceIPAddress_for_user: False

```
2021-06-22T22:57:21.000000Z | arn:aws:sts::591511666666:assumed-role/okta_adm_role/bpatel@splunk.local | ModifySnapshotAttribute | 72.135.232.230
```

**Open #5** (1 event(s))

- user: arn:aws:sts::591511666666:assumed-role/okta_adm_role/bpatel@splunk.local
- events_in_alert: 1
- other_events_for_user: 3
- sourceIPAddress_values: ['72.135.232.230']
- new_sourceIPAddress_for_user: False

```
2021-06-22T22:57:37.000000Z | arn:aws:sts::591511666666:assumed-role/okta_adm_role/bpatel@splunk.local | ModifySnapshotAttribute | 72.135.232.230
```

**Open #6** (1 event(s))

- user: arn:aws:iam::111111111111:user/bhavin_console
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['72.135.1.1']
- new_sourceIPAddress_for_user: False

```
2023-03-20T22:31:36.000000Z | arn:aws:iam::111111111111:user/bhavin_console | ModifySnapshotAttribute | 72.135.1.1
```

## AWS IAM Policy Version Set as Default With Wildcard Actions

3 open, 0 auto-closed.

**Open #1** (1 event(s))

- user: arn:aws:iam::111111111111:user/bhavin_cli
- events_in_alert: 1
- other_events_for_user: 0
- sourceIPAddress_values: ['73.15.72.101']
- new_sourceIPAddress_for_user: True

```
2021-02-23T00:00:16.000000Z | arn:aws:iam::111111111111:user/bhavin_cli | CreatePolicyVersion | 73.15.72.101
```

**Open #2** (1 event(s))

- user: arn:aws:iam::111111111111:user/rhino_escalate
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['73.15.72.101']
- new_sourceIPAddress_for_user: False

```
2021-02-23T00:02:30.000000Z | arn:aws:iam::111111111111:user/rhino_escalate | CreatePolicyVersion | 73.15.72.101
```

**Open #3** (1 event(s))

- user: arn:aws:iam::111111111111:user/rhino_escalate
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['73.15.72.101']
- new_sourceIPAddress_for_user: False

```
2021-02-23T00:02:30.000000Z | arn:aws:iam::111111111111:user/rhino_escalate | CreatePolicyVersion | 73.15.72.101
```

## AWS IAM Role Created Trusting Any Principal or a Whole Account

2 open, 0 auto-closed.

**Open #1** (1 event(s))

- user: arn:aws:sts::900000000002:assumed-role/test-actor-0001/test-session-0001
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['192.0.2.1']
- new_sourceIPAddress_for_user: False

```
2026-11-11T14:43:58.000000Z | arn:aws:sts::900000000002:assumed-role/test-actor-0001/test-session-0001 | CreateRole | 192.0.2.1
```

**Open #2** (1 event(s))

- user: arn:aws:sts::900000000002:assumed-role/test-actor-0001/test-session-0001
- events_in_alert: 1
- other_events_for_user: 1
- sourceIPAddress_values: ['192.0.2.1']
- new_sourceIPAddress_for_user: False

```
2026-11-11T14:43:59.000000Z | arn:aws:sts::900000000002:assumed-role/test-actor-0001/test-session-0001 | CreateRole | 192.0.2.1
```

## AWS S3 Mass Object Download by One Identity

1 open, 0 auto-closed.

**Open #1** (100 event(s))

- user: arn:aws:iam::111111111111:user/console
- events_in_alert: 100
- other_events_for_user: 0
- sourceIPAddress_values: ['12.26.0.38']
- new_sourceIPAddress_for_user: True

```
2023-04-11T01:18:47.000000Z | arn:aws:iam::111111111111:user/console | GetObject | 12.26.0.38
2023-04-11T01:18:47.000000Z | arn:aws:iam::111111111111:user/console | GetObject | 12.26.0.38
2023-04-11T01:18:47.000000Z | arn:aws:iam::111111111111:user/console | GetObject | 12.26.0.38
2023-04-11T01:18:47.000000Z | arn:aws:iam::111111111111:user/console | GetObject | 12.26.0.38
2023-04-11T01:18:47.000000Z | arn:aws:iam::111111111111:user/console | GetObject | 12.26.0.38
... 95 more
```

## Data Access Within One Hour of a Multi-IP Entra Session

1 open, 0 auto-closed.

**Open #1** (4 event(s))

- user: user15@splunkresearch.onmicrosoft.com
- events_in_alert: 4
- other_events_for_user: 10
- IPAddress_values: ['52.88.103.113', '54.68.231.63']
- new_IPAddress_for_user: True
- Location_values: ['US']
- new_Location_for_user: False

```
2023-12-04T20:37:31.000000Z | user15@splunkresearch.onmicrosoft.com | OfficeHome | 52.88.103.113
2023-12-04T20:41:59.000000Z | user15@splunkresearch.onmicrosoft.com | OfficeHome | 54.68.231.63
2023-12-04T20:42:05.000000Z | user15@splunkresearch.onmicrosoft.com | Office 365 Exchange Online | 54.68.231.63
2023-12-04T20:42:32.000000Z | user15@splunkresearch.onmicrosoft.com | MailItemsAccessed | -
```

## M365 Mass File Access or Download by One User

4 open, 0 auto-closed.

**Open #1** (51 event(s))

- user: attacker1@attack_range.lan
- events_in_alert: 51
- other_events_for_user: 0
- ClientIP_values: ['189.135.168.197']
- new_ClientIP_for_user: True

```
2025-01-24T19:39:18.000000Z | attacker1@attack_range.lan | FileAccessed | 189.135.168.197
2025-01-24T19:39:18.000000Z | attacker1@attack_range.lan | FileAccessed | 189.135.168.197
2025-01-24T19:39:18.000000Z | attacker1@attack_range.lan | FileAccessed | 189.135.168.197
2025-01-24T19:39:18.000000Z | attacker1@attack_range.lan | FileAccessed | 189.135.168.197
2025-01-24T19:39:18.000000Z | attacker1@attack_range.lan | FileAccessed | 189.135.168.197
... 46 more
```

**Open #2** (58 event(s))

- user: attacker2@attack_range.lan
- events_in_alert: 58
- other_events_for_user: 0
- ClientIP_values: ['111.132.198.127']
- new_ClientIP_for_user: True

```
2025-01-24T19:26:38.000000Z | attacker2@attack_range.lan | FileDownloaded | 111.132.198.127
2025-01-24T19:26:44.000000Z | attacker2@attack_range.lan | FileDownloaded | 111.132.198.127
2025-01-24T19:26:47.000000Z | attacker2@attack_range.lan | FileDownloaded | 111.132.198.127
2025-01-24T19:26:49.000000Z | attacker2@attack_range.lan | FileDownloaded | 111.132.198.127
2025-01-24T19:26:52.000000Z | attacker2@attack_range.lan | FileDownloaded | 111.132.198.127
... 53 more
```

**Open #3** (66 event(s))

- user: attacker3@attack_range.lan
- events_in_alert: 66
- other_events_for_user: 0
- ClientIP_values: ['214.133.161.103']
- new_ClientIP_for_user: True

```
2025-01-23T02:27:19.000000Z | attacker3@attack_range.lan | FileSyncDownloadedFull | 214.133.161.103
2025-01-23T02:27:20.000000Z | attacker3@attack_range.lan | FileSyncDownloadedFull | 214.133.161.103
2025-01-23T02:27:20.000000Z | attacker3@attack_range.lan | FileSyncDownloadedFull | 214.133.161.103
2025-01-23T02:27:20.000000Z | attacker3@attack_range.lan | FileSyncDownloadedFull | 214.133.161.103
2025-01-23T02:27:20.000000Z | attacker3@attack_range.lan | FileSyncDownloadedFull | 214.133.161.103
... 61 more
```

**Open #4** (58 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 58
- other_events_for_user: 0
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: True

```
2025-01-24T19:26:38.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
2025-01-24T19:26:44.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
2025-01-24T19:26:47.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
2025-01-24T19:26:49.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
2025-01-24T19:26:52.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
... 53 more
```

## M365 File Download With Rclone User Agent

58 open, 0 auto-closed.

**Open #1** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:26:38.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #2** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:26:44.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #3** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:26:47.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #4** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:26:49.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #5** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:26:52.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #6** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:26:54.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #7** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:26:58.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #8** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:01.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #9** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:05.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #10** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:08.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #11** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:11.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #12** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:13.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #13** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:16.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #14** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:19.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #15** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:22.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #16** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:23.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #17** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:25.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #18** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:28.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #19** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:29.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #20** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:33.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #21** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:36.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #22** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:39.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #23** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:43.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #24** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:47.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #25** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:51.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #26** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:55.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #27** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:56.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #28** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:58.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #29** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:27:59.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #30** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:01.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #31** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:03.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #32** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:07.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #33** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:11.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #34** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:16.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #35** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:20.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #36** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:22.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #37** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:24.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #38** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:25.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #39** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:29.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #40** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:31.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #41** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:33.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #42** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:36.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #43** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:41.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #44** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:46.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #45** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:48.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #46** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:50.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #47** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:51.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #48** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:53.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #49** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:54.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #50** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:56.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #51** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:28:58.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #52** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:29:00.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #53** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:29:03.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #54** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:29:07.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #55** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:29:10.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #56** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:29:13.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #57** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:29:18.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

**Open #58** (1 event(s))

- user: external.attacker1_badguy.com#ext#@attack_range.lan
- events_in_alert: 1
- other_events_for_user: 57
- ClientIP_values: ['111.132.178.152']
- new_ClientIP_for_user: False

```
2025-01-24T19:29:22.000000Z | external.attacker1_badguy.com#ext#@attack_range.lan | FileDownloaded | 111.132.178.152
```

## M365 Search for Credential or Payroll Terms

12 open, 0 auto-closed.

**Open #1** (1 event(s))

- user: attacker_1@attackrange.local
- events_in_alert: 1
- other_events_for_user: 0
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: True

```
2024-12-10T16:13:47.000000Z | attacker_1@attackrange.local | SearchQueryPerformed | 174.97.106.111
```

**Open #2** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-24T21:00:52.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

**Open #3** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-24T21:01:52.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

**Open #4** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-24T21:02:50.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

**Open #5** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-24T21:03:52.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

**Open #6** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-25T13:51:06.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedSharePoint | 174.97.106.111
```

**Open #7** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-25T13:52:06.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedSharePoint | 174.97.106.111
```

**Open #8** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-25T13:55:06.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedSharePoint | 174.97.106.111
```

**Open #9** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-26T15:54:42.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

**Open #10** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-26T15:55:05.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

**Open #11** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-26T15:55:34.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

**Open #12** (1 event(s))

- user: attacker_3@attackrange.local
- events_in_alert: 1
- other_events_for_user: 15
- ClientIP_values: ['174.97.106.111']
- new_ClientIP_for_user: False

```
2025-02-26T15:55:52.000000Z | attacker_3@attackrange.local | SearchQueryInitiatedExchange | 174.97.106.111
```

## Entra ID Sign-In Using Device Code Flow

1 open, 0 auto-closed.

**Open #1** (1 event(s))

- user: donald.reed@splunkresearch.com
- events_in_alert: 1
- other_events_for_user: 11
- IPAddress_values: ['4.4.4.4']
- new_IPAddress_for_user: False
- AutonomousSystemNumber_values: ['12252']
- new_AutonomousSystemNumber_for_user: False
- Location_values: ['US']
- new_Location_for_user: False

```
2023-08-03T21:59:28.593828Z | donald.reed@splunkresearch.com | Microsoft Office | 4.4.4.4
```

## Entra ID User Consent Granted to an Application

1 open, 0 auto-closed.

**Open #1** (1 event(s))

- user: None
- events_in_alert: 1

```
2023-10-27T19:03:15.260232Z | ? | Consent to application | -
```

## Entra ID User Session Active From Multiple IPs Within One Hour

3 open, 0 auto-closed.

**Open #1** (10 event(s))

- user: donald.reed@splunkresearch.com
- events_in_alert: 10
- other_events_for_user: 2
- IPAddress_values: ['2800:200:e6f0:660:dca9:aac6:f979:dd14', '4.4.4.4']
- new_IPAddress_for_user: True
- AutonomousSystemNumber_values: ['12252']
- new_AutonomousSystemNumber_for_user: False
- Location_values: ['US']
- new_Location_for_user: False

```
2023-08-03T21:58:05.115306Z | donald.reed@splunkresearch.com | OfficeHome | 2800:200:e6f0:660:dca9:aac6:f979:dd14
2023-08-03T21:58:06.228481Z | donald.reed@splunkresearch.com | Microsoft 365 App Catalog Services | 2800:200:e6f0:660:dca9:aac6:f979:dd14
2023-08-03T21:58:06.312863Z | donald.reed@splunkresearch.com | Microsoft Office 365 Portal | 2800:200:e6f0:660:dca9:aac6:f979:dd14
2023-08-03T21:58:06.676136Z | donald.reed@splunkresearch.com | Office365 Shell WCSS-Client | 2800:200:e6f0:660:dca9:aac6:f979:dd14
2023-08-03T21:58:06.828503Z | donald.reed@splunkresearch.com | Office365 Shell WCSS-Client | 2800:200:e6f0:660:dca9:aac6:f979:dd14
... 5 more
```

**Open #2** (3 event(s))

- user: user15@splunkresearch.onmicrosoft.com
- events_in_alert: 3
- other_events_for_user: 6
- IPAddress_values: ['52.88.103.113', '54.68.231.63']
- new_IPAddress_for_user: True
- Location_values: ['US']
- new_Location_for_user: False

```
2023-12-04T20:37:31.000000Z | user15@splunkresearch.onmicrosoft.com | OfficeHome | 52.88.103.113
2023-12-04T20:41:59.000000Z | user15@splunkresearch.onmicrosoft.com | OfficeHome | 54.68.231.63
2023-12-04T20:42:05.000000Z | user15@splunkresearch.onmicrosoft.com | Office 365 Exchange Online | 54.68.231.63
```

**Open #3** (22 event(s))

- user: user30@splunkresearch.com
- events_in_alert: 22
- other_events_for_user: 0
- IPAddress_values: ['34.1.3.194', '52.2.3.136']
- new_IPAddress_for_user: True
- AutonomousSystemNumber_values: ['16509']
- new_AutonomousSystemNumber_for_user: True
- Location_values: ['US']
- new_Location_for_user: True

```
2023-01-12T18:21:20.625328Z | user30@splunkresearch.com | OfficeHome | 34.1.3.194
2023-01-12T18:21:20.866450Z | user30@splunkresearch.com | OfficeHome | 34.1.3.194
2023-01-12T18:21:20.874351Z | user30@splunkresearch.com | OfficeHome | 34.1.3.194
2023-01-12T18:21:20.882307Z | user30@splunkresearch.com | OfficeHome | 34.1.3.194
2023-01-12T18:21:20.886700Z | user30@splunkresearch.com | OfficeHome | 34.1.3.194
... 17 more
```

