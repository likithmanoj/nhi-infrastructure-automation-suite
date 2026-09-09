import json
import logging

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "nhi-risk-analyzer"
TOOL_VERSION = "0.1.0"


def map_severity_to_sarif_level(severity: str) -> str:
    """Maps NHI findings severity to valid SARIF v2.1.0 levels."""
    if not isinstance(severity, str):
        return "warning"
    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    return severity_map.get(severity.strip().upper(), "warning")


def build_sarif_result(finding: dict) -> dict:
    """Converts a single NHI finding dictionary into a SARIF result object."""
    rule_id = finding.get("RuleID", "UNKNOWN")
    severity = finding.get("Severity", "warning")
    level = map_severity_to_sarif_level(severity)

    # Prefer detailed finding description, fall back to Title
    message_text = (
        finding.get("Title")
        or finding.get("Finding")
        or f"Security rule violation detected for {rule_id}"
    )

    identity_name = finding.get("IdentityName", "Unknown")
    identity_type = finding.get("IdentityType", "Identity")
    resource = finding.get("Resource", "*")

    result = {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": f"{message_text} (Target: {identity_type}/{identity_name}, Resource: {resource})"
        },
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": identity_name,
                        "kind": identity_type,
                    }
                ]
            }
        ],
    }

    return result


def build_sarif_rules(findings: list[dict]) -> list[dict]:
    """Dynamically builds rule metadata for all distinct rules observed in findings."""
    rules_dict = {}
    for finding in findings:
        rule_id = finding.get("RuleID", "UNKNOWN")
        if rule_id not in rules_dict:
            title = finding.get("Title") or finding.get("Finding") or rule_id
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "defaultConfiguration": {
                    "level": map_severity_to_sarif_level(finding.get("Severity", "warning"))
                },
            }
    return list(rules_dict.values())


def export_findings_to_sarif(findings: list[dict], filepath: str) -> None:
    """Serializes findings list into a SARIF v2.1.0 JSON file."""
    sarif_results = [build_sarif_result(f) for f in findings if isinstance(f, dict)]
    sarif_rules = build_sarif_rules(findings)

    sarif_document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/likithmanoj/nhi-risk-analyzer",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_document, f, indent=2)
        logger.info(f"Successfully exported {len(sarif_results)} findings to SARIF: {filepath}")
    except IOError as e:
        logger.error(f"Failed to write SARIF report to {filepath}: {e}")
        raise