import argparse
from nhi.services.inventory import create_inventory
from nhi.risk.rules.wildcards import (
    analyze_policy,                                    # IAM_01 (Wildcard Actions), IAM_02 (Wildcard Resources), IAM_03 (Admin-equivalent)
    analyze_admin_access,                              # IAM_03 (AdministratorAccess managed policy)
)
from nhi.risk.rules.credentials import (
    analyze_stale_access_keys,                         # IAM_11 (Stale Access Keys >90 days)
    analyze_unused_keys,                               # IAM_12 (Unused Access Keys >30 days)
)
from nhi.risk.rules.privilege_escalation import (
    analyze_passrole_with_wildcard,                    # IAM_04 (PassRole escalation)
    analyze_create_policy_version,                     # IAM_05 (CreatePolicyVersion escalation)
    analyze_policy_for_policy_attachment_escalation,   # IAM_06 (Policy attachment escalation)
    analyze_access_key_creation_escalation,            # IAM_07 (CreateAccessKey escalation)
    analyze_console_access_escalation,                 # IAM_08 (LoginProfile escalation)
    analyze_policy_for_set_policy_version,             # IAM_09 (SetDefaultPolicyVersion escalation)
)
from nhi.risk.rules.data_perimeter import (
    analyze_policy_for_s3_exfiltration,                # IAM_14 (S3 Exfiltration)
    analyze_policy_for_kms_decryption,                 # IAM_16 (KMS Decryption)
)
from nhi.risk.rules.resource_protection import (
    analyze_policy_for_defense_evasion,                # IAM_15 (Defense Evasion / Log tampering)
)
from nhi.remediation.dispatch import dispatch_remediation
from nhi.risk.rules.tags import analyze_mandatory_tags # TAG_01 (Missing mandatory tags)
from nhi.risk.rules.trust_policy import analyze_trust_policy # IAM_10 (Permissive trust policies
from datetime import datetime, timezone
from nhi.aws.s3 import fetch_latest_scan, persist_scan_artifact
from nhi.remediation.diff import diff_findings

def run_privilege_escalation_checks(policies, identity_type, identity_name):
    """Sub-runner to execute all privilege escalation rules against a policy list."""
    findings = []
    findings.extend(analyze_passrole_with_wildcard(policies, identity_type, identity_name))
    findings.extend(analyze_create_policy_version(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_policy_attachment_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_access_key_creation_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_console_access_escalation(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_set_policy_version(policies, identity_type, identity_name))
    return findings


def run_resource_protection_checks(policies, identity_type, identity_name):
    """Sub-runner to execute data perimeter and defense evasion rules against a policy list."""
    findings = []
    findings.extend(analyze_policy_for_s3_exfiltration(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_defense_evasion(policies, identity_type, identity_name))
    findings.extend(analyze_policy_for_kms_decryption(policies, identity_type, identity_name))
    return findings


def analyze_inventory():
    response = create_inventory()

    users = response.get("users", [])
    groups = response.get("groups", [])
    roles = response.get("roles", [])

    findings = []

    for user in users:
        username = user['UserName']
        attached = user.get('AttachedPolicies', [])
        inline = user.get('InlinePolicies', [])
        access_keys = user.get('AccessKeys', [])      
        findings.extend(analyze_policy(attached, "User", username))
        findings.extend(analyze_policy(inline, "User", username))
        findings.extend(analyze_admin_access(attached, "User", username))       
        findings.extend(analyze_stale_access_keys(access_keys, username))
        findings.extend(analyze_unused_keys(access_keys, username))     
        findings.extend(run_privilege_escalation_checks(attached, "User", username))
        findings.extend(run_privilege_escalation_checks(inline, "User", username))
        findings.extend(run_resource_protection_checks(attached, "User", username))
        findings.extend(run_resource_protection_checks(inline, "User", username))
        findings.extend(analyze_mandatory_tags(user, "User"))

    for group in groups:
        group_name = group['GroupName']
        attached = group.get('AttachedPolicies', [])
        inline = group.get('InlinePolicies', [])      
        findings.extend(analyze_policy(attached, "Group", group_name))
        findings.extend(analyze_policy(inline, "Group", group_name))
        findings.extend(analyze_admin_access(attached, "Group", group_name))     
        findings.extend(run_privilege_escalation_checks(attached, "Group", group_name))
        findings.extend(run_privilege_escalation_checks(inline, "Group", group_name))
        findings.extend(run_resource_protection_checks(attached, "Group", group_name))
        findings.extend(run_resource_protection_checks(inline, "Group", group_name))

    for role in roles:
        role_name = role['RoleName']
        attached = role.get('AttachedPolicies', [])
        inline = role.get('InlinePolicies', [])        
        findings.extend(analyze_policy(attached, "Role", role_name))
        findings.extend(analyze_policy(inline, "Role", role_name))
        findings.extend(analyze_admin_access(attached, "Role", role_name))        
        findings.extend(run_privilege_escalation_checks(attached, "Role", role_name))
        findings.extend(run_privilege_escalation_checks(inline, "Role", role_name))
        findings.extend(run_resource_protection_checks(attached, "Role", role_name))
        findings.extend(run_resource_protection_checks(inline, "Role", role_name))
        findings.extend(analyze_mandatory_tags(role, "Role"))
        trust_policy = role.get("TrustPolicy", {})
        findings.extend(analyze_trust_policy(trust_policy, role_name))

    findings = enrich_findings_for_aws_managed_policies(findings)

    return findings

def enrich_findings_for_aws_managed_policies(findings):
    for finding in findings:
        arn = finding.get("PolicyArn")  # note: match the exact key you actually write elsewhere
        if arn:
            is_aws_managed = is_aws_managed_policy(arn)
            finding["RemediationEligible"] = not is_aws_managed
            if is_aws_managed:
                finding["RemediationNote"] = "AWS-managed policy — cannot be rewritten. Detach or replace with a customer-managed equivalent."
                
    return findings


def is_aws_managed_policy(policy_arn) -> bool:
    return bool(policy_arn and policy_arn.startswith("arn:aws:iam::aws:policy/"))

def main():
    parser = argparse.ArgumentParser(
        description="NHI Risk Analyzer & Remediation Engine for AWS"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate remediation actions without making changes in AWS",
    )
    group.add_argument(
        "--remediate",
        action="store_true",
        help="Execute live remediation against detected findings",
    )

    args = parser.parse_args()

    print("[*] Running inventory and risk evaluation...")
    all_findings = analyze_inventory()
    print(f"[*] Total current findings detected: {len(all_findings)}")

    print("[*] Fetching previous scan artifact from S3 for run-over-run diffing...")
    previous_scan = fetch_latest_scan()
    previous_findings = previous_scan.get("findings", []) if previous_scan else []

    diff_result = diff_findings(previous_findings, all_findings)
    summary = diff_result["summary"]

    print(f"\n{'='*40}")
    print("           RUN-OVER-RUN DIFF            ")
    print(f"{'='*40}")
    print(f" [+] New Findings:        {summary['new_count']}")
    print(f" [-] Resolved Findings:   {summary['resolved_count']}")
    print(f" [=] Unresolved Findings: {summary['unresolved_count']}")
    print(f"{'='*40}\n")

    stats = None
    if args.remediate:
        print("[!] Executing LIVE remediation...")
        stats = dispatch_remediation(all_findings, dry_run=False)
        print("Live Remediation Stats:", stats)
    elif args.dry_run:
        print("[*] Executing DRY RUN simulation...")
        stats = dispatch_remediation(all_findings, dry_run=True)
        print("Dry Run Stats:", stats)
    else:
        print(
            "[*] Scan complete. (Pass --dry-run to simulate containment or --remediate to execute live)"
        )

    artifact = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "diff": diff_result,
        "findings": all_findings,
        "remediation_stats": stats,
    }
    print("[*] Persisting scan artifact to S3...")
    persist_scan_artifact(artifact)


if __name__ == "__main__":
    main()