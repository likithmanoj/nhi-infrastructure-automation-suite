import pytest
from nhi.remediation.diff import diff_findings, get_finding_key


def test_get_finding_key_handles_missing_policy_name():
    finding = {"IdentityName": "AppRole", "RuleID": "IAM_01"}
    assert get_finding_key(finding) == ("AppRole", "IAM_01", "")


def test_diff_findings_first_scan_all_new():
    previous = []
    current = [
        {"IdentityName": "DeployerRole", "RuleID": "IAM_01", "PolicyName": "FullAdmin"},
        {"IdentityName": "LambdaRunner", "RuleID": "IAM_02", "PolicyName": "S3Wildcard"},
    ]

    result = diff_findings(previous, current)

    assert result["summary"]["new_count"] == 2
    assert result["summary"]["resolved_count"] == 0
    assert result["summary"]["unresolved_count"] == 0
    assert len(result["new"]) == 2
    assert result["resolved"] == []
    assert result["unresolved"] == []


def test_diff_findings_categorization():
    previous = [
        # Will be resolved (absent in current)
        {"IdentityName": "StaleServiceRole", "RuleID": "IAM_03", "PolicyName": "OldPolicy"},
        # Will remain unresolved (present in both)
        {"IdentityName": "AppRole", "RuleID": "IAM_01", "PolicyName": "AdminPolicy"},
    ]

    current = [
        # Unresolved
        {"IdentityName": "AppRole", "RuleID": "IAM_01", "PolicyName": "AdminPolicy"},
        # New finding
        {"IdentityName": "WorkerRole", "RuleID": "IAM_02", "PolicyName": "WriteAccess"},
    ]

    result = diff_findings(previous, current)

    assert result["summary"]["new_count"] == 1
    assert result["summary"]["resolved_count"] == 1
    assert result["summary"]["unresolved_count"] == 1

    assert result["new"][0]["IdentityName"] == "WorkerRole"
    assert result["resolved"][0]["IdentityName"] == "StaleServiceRole"
    assert result["unresolved"][0]["IdentityName"] == "AppRole"