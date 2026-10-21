"""Renders a MITRE ATT&CK coverage map (markdown + svg) showing which techniques the rules detect.

Sigma rules carry ATT&CK tags like `attack.t1078.004`. This module reads those
tags, compares them with the techniques this lab's attack chain is supposed to
cover, and gives every technique one of three statuses:

  tested   - a rule is tagged with it AND that rule caught at least one malicious event
  untested - a rule is tagged with it, but it has not caught anything yet
  gap      - no rule covers it at all

"Tested" is the only status worth claiming on a resume: it means the rule was
proven against attack telemetry, not just written.
"""

from html import escape

# The techniques the attack chain is meant to cover, in chain order.
# (technique id, technique name, which branch of the chain it belongs to)
PLANNED_TECHNIQUES = [
    ("T1566", "Phishing", "Identity"),
    ("T1528", "Steal Application Access Token", "Identity"),
    ("T1539", "Steal Web Session Cookie", "Identity"),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "Identity"),
    ("T1530", "Data from Cloud Storage", "Data"),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "AWS"),
    ("T1098.003", "Account Manipulation: Additional Cloud Roles", "AWS"),
    ("T1537", "Transfer Data to Cloud Account", "AWS"),
]

STATUS_COLORS = {"tested": "#2e7d32", "untested": "#f9a825", "gap": "#9e9e9e"}


def techniques_in_rule(rule):
    """Return the ATT&CK technique ids a rule is tagged with, e.g. {'T1078.004'}."""
    techniques = set()
    for tag in rule.get("tags", []):
        tag = str(tag).lower()
        # Technique tags look like attack.t1234 or attack.t1234.001; tactic tags
        # (attack.initial_access) do not start with "t" + a digit, so they are skipped.
        if tag.startswith("attack.t") and tag[8:9].isdigit():
            techniques.add(tag[len("attack."):].upper())
    return techniques


def build_coverage(rule_results):
    """Work out each planned technique's status.

    `rule_results` is a list of dicts with keys: rule (title), techniques (set of ids),
    true_positives (int). Returns a list of dicts, one per planned technique.
    """
    coverage = []
    for technique_id, name, branch in PLANNED_TECHNIQUES:
        covering = [result for result in rule_results if technique_id in result["techniques"]]
        if any(result["true_positives"] > 0 for result in covering):
            status = "tested"
        elif covering:
            status = "untested"
        else:
            status = "gap"
        coverage.append({
            "id": technique_id,
            "name": name,
            "branch": branch,
            "status": status,
            "rules": [result["rule"] for result in covering],
        })
    return coverage


def coverage_markdown(coverage):
    """Render the coverage list as a markdown table."""
    lines = [
        "| Branch | Technique | Name | Status | Rules |",
        "|---|---|---|---|---|",
    ]
    for item in coverage:
        rules = ", ".join(item["rules"]) if item["rules"] else "-"
        lines.append(
            f"| {item['branch']} | {item['id']} | {item['name']} | {item['status']} | {rules} |"
        )
    return "\n".join(lines) + "\n"


def coverage_svg(coverage):
    """Render the coverage list as a simple SVG: one colored box per technique, grouped by branch."""
    box_width, box_height, gap, label_width = 230, 56, 10, 90
    branches = []
    for item in coverage:
        if item["branch"] not in branches:
            branches.append(item["branch"])
    most_per_row = max(sum(1 for item in coverage if item["branch"] == b) for b in branches)
    width = label_width + most_per_row * (box_width + gap) + gap
    height = 50 + len(branches) * (box_height + gap) + 40

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="Segoe UI, Helvetica, Arial, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        '<text x="10" y="28" font-size="18" font-weight="bold" fill="#212121">'
        "ATT&amp;CK coverage: identity-to-data chain</text>",
    ]
    for row, branch in enumerate(branches):
        y = 45 + row * (box_height + gap)
        parts.append(
            f'<text x="10" y="{y + box_height / 2 + 5}" font-size="14" fill="#212121">'
            f"{escape(branch)}</text>"
        )
        in_branch = [item for item in coverage if item["branch"] == branch]
        for column, item in enumerate(in_branch):
            x = label_width + column * (box_width + gap)
            parts.append(
                f'<rect x="{x}" y="{y}" width="{box_width}" height="{box_height}" rx="6" '
                f'fill="{STATUS_COLORS[item["status"]]}"/>'
            )
            parts.append(
                f'<text x="{x + 8}" y="{y + 22}" font-size="14" font-weight="bold" fill="#ffffff">'
                f'{escape(item["id"])} ({item["status"]})</text>'
            )
            parts.append(
                f'<text x="{x + 8}" y="{y + 42}" font-size="11" fill="#ffffff">'
                f'{escape(item["name"][:36])}</text>'
            )
    legend_y = height - 18
    legend_x = 10
    for status, color in STATUS_COLORS.items():
        parts.append(f'<rect x="{legend_x}" y="{legend_y - 11}" width="14" height="14" fill="{color}"/>')
        parts.append(f'<text x="{legend_x + 20}" y="{legend_y}" font-size="12" fill="#212121">{status}</text>')
        legend_x += 100
    parts.append("</svg>")
    return "\n".join(parts) + "\n"
