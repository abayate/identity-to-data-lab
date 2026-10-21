"""The shape of every log record in data/sample-logs/, one schema per log type.

Field names follow the Microsoft Sentinel tables the same events land in:
  - entra_signins*.jsonl -> SigninLogs (+ AADNonInteractiveUserSignInLogs,
    AADServicePrincipalSignInLogs; the `Category` field says which)
  - entra_audit*.jsonl   -> AuditLogs
  - m365_audit*.jsonl    -> OfficeActivity (kept with the Office 365 Management API
    field names, which Sentinel mostly keeps as-is)

Using the real names means rules and KQL written against the sample logs work
unchanged against a real tenant later (see docs/05-go-live.md).

Every record also carries three `lab_` fields. They do NOT exist in real logs.
They are the answer key and the paper trail:
  lab_label     "benign" or "malicious"
  lab_scenario  which attack (or normal activity) the event belongs to
  lab_source    which public dataset the event came from
Detection rules must never read `lab_` fields, or the rules would be cheating.

REQUIRED fields must be present with the given type. OPTIONAL fields may be
missing or null (real logs leave plenty of fields empty, e.g. service-principal
sign-ins have no user), but if present they must have the given type.
"""

LAB_FIELDS = {
    "lab_label": str,
    "lab_scenario": str,
    "lab_source": str,
}

SIGNIN_REQUIRED = {
    "TimeGenerated": str,          # ISO 8601 UTC timestamp
    "Category": str,               # SignInLogs / NonInteractiveUserSignInLogs / ServicePrincipalSignInLogs
    "IPAddress": str,              # source IP of the sign-in
    "AppId": str,                  # which application was signed in to
    "ResultType": str,             # "0" = success; anything else is an Entra error code
    "CorrelationId": str,
    **LAB_FIELDS,
}

SIGNIN_OPTIONAL = {
    "UserPrincipalName": str,      # missing for service-principal sign-ins
    "UserId": str,
    "AppDisplayName": str,
    "AutonomousSystemNumber": int, # network owner (ASN) of the IP
    "Location": str,               # two-letter country code
    "LocationDetails": dict,       # city / state / coordinates
    "UserAgent": str,
    "ClientAppUsed": str,
    "AuthenticationProtocol": str, # "deviceCode" for the device-code flow
    "AuthenticationRequirement": str,  # singleFactorAuthentication / multiFactorAuthentication
    "IncomingTokenType": str,      # "none" for a fresh login; e.g. "primaryRefreshToken" for token use
    "ResultDescription": str,
    "ConditionalAccessStatus": str,
    "RiskLevelDuringSignIn": str,
    "IsInteractive": bool,
    "DeviceDetail": dict,
    "ResourceDisplayName": str,
    "UniqueTokenIdentifier": str,
    "SessionId": str,
    "ServicePrincipalName": str,
}

AUDIT_REQUIRED = {
    "TimeGenerated": str,
    "OperationName": str,          # e.g. "Consent to application"
    "Category": str,               # e.g. ApplicationManagement, UserManagement
    "Result": str,                 # success / failure
    "CorrelationId": str,
    "InitiatedBy": dict,           # {"user": {...}} or {"app": {...}}
    "TargetResources": list,
    **LAB_FIELDS,
}

AUDIT_OPTIONAL = {
    "LoggedByService": str,
    "AdditionalDetails": list,
}

M365_REQUIRED = {
    "TimeGenerated": str,
    "Operation": str,              # e.g. FileDownloaded, SearchQueryPerformed, UserLoggedIn
    "Workload": str,               # SharePoint, OneDrive, Exchange, AzureActiveDirectory
    "UserId": str,
    **LAB_FIELDS,
}

M365_OPTIONAL = {
    "ClientIP": str,
    "UserAgent": str,
    "SourceFileName": str,
    "SourceFileExtension": str,
    "SiteUrl": str,
    "SearchQueryText": str,
    "AppAccessContext": dict,      # carries AADSessionId, which links file activity to a sign-in session
}

# CloudTrail keeps AWS's own camelCase field names (Sigma's aws/cloudtrail rules use them,
# and so do Athena and CloudTrail Lake). Sentinel's AWSCloudTrail table renames them; see
# docs/03-detections.md for the mapping used in the KQL.
CLOUDTRAIL_REQUIRED = {
    "TimeGenerated": str,
    "eventTime": str,
    "eventName": str,              # the API call, e.g. CreateAccessKey
    "eventSource": str,            # the service, e.g. iam.amazonaws.com
    "userIdentity": dict,          # who made the call (type, arn, userName, accessKeyId...)
    **LAB_FIELDS,
}

CLOUDTRAIL_OPTIONAL = {
    "sourceIPAddress": str,
    "userAgent": str,
    "errorCode": str,              # e.g. AccessDenied; missing when the call succeeded
    "requestParameters": dict,
    "recipientAccountId": str,
    "awsRegion": str,
}

# Which schema applies to which sample-log file prefix.
SCHEMAS = {
    "entra_signins": (SIGNIN_REQUIRED, SIGNIN_OPTIONAL),
    "entra_audit": (AUDIT_REQUIRED, AUDIT_OPTIONAL),
    "m365_audit": (M365_REQUIRED, M365_OPTIONAL),
    "cloudtrail": (CLOUDTRAIL_REQUIRED, CLOUDTRAIL_OPTIONAL),
}

ALLOWED_LABELS = {"benign", "malicious"}
