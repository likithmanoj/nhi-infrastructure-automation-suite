def get_finding_key(finding: dict) -> tuple:
    return (
        finding.get("IdentityName"),
        finding.get("RuleID"),
        finding.get("PolicyName", ""),
    )


def diff_findings(previous_findings: list[dict], current_findings: list[dict]) -> dict:
    prev_map = {get_finding_key(f): f for f in previous_findings}
    curr_map = {get_finding_key(f): f for f in current_findings}

    new_keys = curr_map.keys() - prev_map.keys()
    resolved_keys = prev_map.keys() - curr_map.keys()
    unresolved_keys = curr_map.keys() & prev_map.keys()

    return {
        "summary": {
            "new_count": len(new_keys),
            "resolved_count": len(resolved_keys),
            "unresolved_count": len(unresolved_keys),
        },
        "new": [curr_map[k] for k in new_keys],
        "resolved": [prev_map[k] for k in resolved_keys],
        "unresolved": [curr_map[k] for k in unresolved_keys],
    }