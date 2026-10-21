"""The shape of one synthetic Entra ID sign-in record.

Field names copy Microsoft's `SigninLogs` table (the one Sentinel / Log
Analytics stores Entra sign-ins in). Using the real names means the Sigma
rules and KQL queries written against these synthetic logs work unchanged
against a real tenant later (see docs/05-go-live.md).

Two extra fields start with `lab_`. They do NOT exist in real Entra logs:
they are the answer key, saying whether an event is benign or part of the
attack. The harness uses them to score true and false positives. Detection
rules must never read them, or the rules would be cheating.
"""

# Fields every sign-in record must have, mapped to the Python type of the value.
REQUIRED_FIELDS = {
    "TimeGenerated": str,              # ISO 8601 UTC timestamp, e.g. "2026-10-01T14:03:22Z"
    "UserPrincipalName": str,          # who signed in, e.g. "alice@contoso.example"
    "AppDisplayName": str,             # which app they signed in to
    "IPAddress": str,                  # source IP of the sign-in
    "AutonomousSystemNumber": int,     # network owner (ASN) of that IP
    "Location": str,                   # two-letter country code
    "UserAgent": str,                  # browser / client string
    "ClientAppUsed": str,              # e.g. "Browser", "Mobile Apps and Desktop clients"
    "AuthenticationProtocol": str,     # "none" normally, "deviceCode" for device-code flow
    "AuthenticationRequirement": str,  # "singleFactorAuthentication" or "multiFactorAuthentication"
    "IncomingTokenType": str,          # "none" for a fresh login, "primaryRefreshToken" etc. for token use
    "ResultType": str,                 # "0" means success; anything else is an error code
    "SessionId": str,                  # ties sign-ins from the same session together
    "CorrelationId": str,              # unique id for this sign-in event
    "lab_label": str,                  # answer key: "benign" or "malicious"
    "lab_scenario": str,               # answer key: which story produced it, e.g. "normal_workday"
}

# The only values allowed in the answer-key field.
ALLOWED_LABELS = {"benign", "malicious"}
