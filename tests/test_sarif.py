import json
import pytest
from nhi.services.sarif import (
    map_severity_to_sarif_level,
    build_sarif_result,
    build_sarif_rules,
    export_findings_to_sarif,
    SARIF_SCHEMA,
    TOOL_NAME,
    TOOL_VERSION,
)


def test_map_severity_to_sarif_level_valid():
    assert map_severity_to_sarif_level("CRITICAL") == "error"
    assert map_severity_to_sarif_level("HIGH") == "error"
    assert map_severity_to_sarif_level("MEDIUM") == "warning"
    assert map_severity_to_sarif_level("LOW") == "note"


def test_map_severity_to_sarif_level_normalization():
    assert map_severity_to_sarif_level("critical") == "error"
    assert map_severity_to_sarif_level("  high  ") == "error"
    assert map_severity_to_sarif_level("Low") == "note"


def test_map_severity_to_sarif_level_fallback():
    assert map_severity_to_sarif_level(None) == "warning"
    assert map_severity_to_sarif_level("") == "warning"
    assert map_severity_to_sarif_level(123) == "warning"
    assert map_severity_to_sarif_level("UNKNOWN_SEVERITY") == "warning"


def test_build_sarif_result():
    finding = {
        "RuleID": "IAM_04",
        "Severity": "HIGH",
        "Title": "Privilege Escalation via iam:PassRole",
        "IdentityType": "Role",
        "IdentityName": "deployer-role",
        "Resource": "*",
    }
    result = build_sarif_result(finding)

    assert result["ruleId"] == "IAM_04"
    assert result["level"] == "error"
    assert "Privilege Escalation via iam:PassRole" in result["message"]["text"]
    assert "(Target: Role/deployer-role, Resource: *)" in result["message"]["text"]
    assert result["locations"][0]["logicalLocations"][0]["name"] == "deployer-role"
    assert result["locations"][0]["logicalLocations"][0]["kind"] == "Role"


def test_build_sarif_rules_deduplication():
    findings = [
        {"RuleID": "IAM_01", "Severity": "HIGH", "Title": "Wildcard Actions"},
        {"RuleID": "IAM_01", "Severity": "HIGH", "Title": "Wildcard Actions"},
        {"RuleID": "IAM_02", "Severity": "LOW", "Title": "Wildcard Resources"},
    ]
    rules = build_sarif_rules(findings)

    assert len(rules) == 2
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"IAM_01", "IAM_02"}


def test_export_findings_to_sarif(tmp_path):
    output_file = tmp_path / "results.sarif"
    findings = [
        {
            "RuleID": "IAM_04",
            "Severity": "HIGH",
            "Title": "PassRole escalation",
            "IdentityType": "User",
            "IdentityName": "nhi-test-user",
            "Resource": "*",
        },
        {
            "RuleID": "TAG_01",
            "Severity": "LOW",
            "Title": "Missing tags",
            "IdentityType": "Role",
            "IdentityName": "runner-role",
            "Resource": "arn:aws:iam::123456789012:role/runner-role",
        },
    ]

    export_findings_to_sarif(findings, str(output_file))

    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["$schema"] == SARIF_SCHEMA
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == TOOL_NAME
    assert run["tool"]["driver"]["version"] == TOOL_VERSION
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2


def test_export_findings_empty_list(tmp_path):
    output_file = tmp_path / "empty.sarif"
    export_findings_to_sarif([], str(output_file))

    assert output_file.exists()
    with open(output_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []
