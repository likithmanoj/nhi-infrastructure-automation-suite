# NHI Risk Analyzer and Remediator for AWS

An offline-first security automation platform that discovers, inventories, analyzes, risk-assesses, and safely remediates **Non-Human Identities (NHIs)** — IAM users, groups, roles, and associated policies — across AWS environments.

> ⭐️ **If you find this tool helpful for auditing and securing AWS Non-Human Identities, please consider starring the repository!**

---

---

## 📋 Overview

**NHI Risk Analyzer** addresses a critical cloud security challenge: enterprise AWS environments accumulate hundreds of non-human identities (service accounts, automation roles, CI/CD credentials, cross-account roles) with minimal visibility into which identities are over-privileged, dormant, or introduce privilege-escalation risk.

The platform enforces strict architectural decoupling across three distinct phases:
1. **State Collection:** Live AWS ingestion into an `inventory.json` snapshot via Boto3.
2. **Offline Risk Evaluation:** Evaluating IAM security rules against the snapshot without live network dependencies. This means the risk engine can be re-run, tested, and iterated on without touching AWS again, and every finding is reproducible against the exact account state it was generated from.
3. **Automated Remediation & Containment:** A fail-closed containment pipeline that neutralizes dangerous escalation attack paths via Permissions Boundaries and deactivates stale/dormant credentials without causing operational microservice outages.

---

## 🎯 Why This Project Exists

Enterprise AWS environments routinely contain non-human identities that are:

- **Unstandardized:** Created manually without consistent provisioning standards.
- **Over-Permissioned:** Granted administrative or wildcard permissions far exceeding actual operational needs.
- **Dormant & Forgotten:** Left active long after workloads or integration pipelines have been decommissioned.
- **Incompletely Audited:** Carrying inline policies that bypass standard managed-policy checks.
- **Credential Risks:** Utilizing access keys that are stale (>90 days old) or have never been used since inception.
- **Escalation-Prone:** Holding IAM permissions that, alone or combined, allow privilege escalation to full administrator access — documented attack paths that most policy-only scanners don't check for.

NHI Risk Analyzer automates discovery, security analysis, and targeted remediation using live AWS APIs and offline rule processing.

---

## 🏗️ Architecture & Workflow

```text
  ┌──────────────┐         ┌──────────────────┐         ┌─────────────────┐
  │   AWS IAM    │ ──────> │   inventory.py   │ ──────> │  inventory.json │
  │   APIs       │  boto3  │ (State Collector)│         │   (Raw Snapshot)│
  └──────────────┘         └──────────────────┘         └────────┬────────┘
                                                                 │
                                                                 ▼
  ┌──────────────┐         ┌──────────────────┐         ┌─────────────────┐
  │  S3 Snapshot │ <────── │      export.py   │ <────── │     risk.py     │
  │   Storage    │  upload │   (S3 Export)    │         │ (Offline Engine)│
  └──────────────┘         └──────────────────┘         └────────┬────────┘
                                                                 │
                                                                 ▼
                                                        ┌─────────────────┐
                                                        │   dispatch.py   │
                                                        │  (Remediation)  │
                                                        └────────┬────────┘
                                                                 │
                                       ┌─────────────────────────┴────────────────────────┐
                                       ▼                                                  ▼
                            ┌─────────────────────┐                            ┌─────────────────────┐
                            │      policy.py      │                            │    credential.py    │
                            │ (Attach Boundary)   │                            │ (Deactivate Key)    │
                            └─────────────────────┘                            └─────────────────────┘
```

1. **State Collection (`nhi/services/inventory.py`):** Queries AWS IAM APIs via Boto3, enriches user access key metadata with `GetAccessKeyLastUsed` details, and serializes a clean state snapshot to `inventory.json`.
2. **Offline Evaluation (`nhi/risk/risk.py`):** Loads `inventory.json` locally and passes resource payloads through modular security rules inside `nhi/risk/rules/`.
3. **Artifact Export & Run-over-Run Diffing (`nhi/services/export.py`, `nhi/remediation/diff.py`):** Calculates security drift against historical baseline scans, uploads execution artifacts to S3, and optionally exports findings to CSV for spreadsheet auditing.
4. **Remediation Dispatcher (`nhi/remediation/dispatch.py`):** Routes actionable findings through safe containment handlers with fail-closed safety, dry-run simulation mode, and exemption filtering via `nhi-ignore.yaml`.

---

## ⚡ Engineering Optimizations

### AWS Session Caching

To eliminate redundant AWS STS authentication calls during inventory collection, authenticated `boto3.Session` objects are cached for the lifetime of the Python process in `nhi/aws/session.py`.

* **STS `AssumeRole` calls reduced:** `35` → `1`
* **Inventory execution time reduced:** `79.58s` → `45.67s` (~**43% runtime improvement**)
* **Encapsulation:** Authentication remains fully encapsulated inside `session.py`, requiring zero logic changes to discovery or rule modules.

---

## 🛡️ Rule Coverage & Remediation Mapping

Rule IDs are grouped by category rather than numbered strictly sequentially — `IAM_01–03` cover general policy analysis, `IAM_04–08` cover documented privilege-escalation paths, and `IAM_11–12` cover credential hygiene. `IAM_09–10` are reserved for planned trust-policy analysis.

| Rule ID | Name | Category | Severity | Status | Remediation Action |
|:---|:---|:---|:---|:---|:---|
| **`IAM_01`** | Wildcard Actions in Policies | Policy Analysis | `HIGH` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`IAM_02`** | Wildcard Resources in Policies | Policy Analysis | `HIGH` / `LOW` (scoped-prefix downgrade) | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`IAM_03`** | Full Administrator Access | Policy Analysis | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (detach planned for Phase 5) |
| **`IAM_04`** | Privilege Escalation via `iam:PassRole` | Privilege Escalation | `HIGH` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_05`** | Privilege Escalation via `iam:CreatePolicyVersion` | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_06`** | Direct Escalation via Policy Attachment (`Attach*`/`Put*`) | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_07`** | Privilege Escalation via `iam:CreateAccessKey` | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_08`** | Console Access Escalation (`Create`/`UpdateLoginProfile`) | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_09`** | Privilege Escalation via `iam:SetDefaultPolicyVersion` | Privilege Escalation | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (Explicit Deny) |
| **`IAM_10`** | Permissive Role Trust Policies (`*` AssumeRole Principal) | Trust Policy Analysis | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`IAM_11`** | Stale Access Keys (>90 Days Old) | Credential Security | `HIGH` / `LOW` | ✅ Implemented | Deactivate Key (`Status: Inactive`) |
| **`IAM_12`** | Unused & Dormant Access Keys (>30 Days) | Credential Security | `HIGH` | ✅ Implemented | Deactivate Key (`Status: Inactive`) |
| **`IAM_14`** | Unrestricted S3 Data Exfiltration (`s3:GetObject*`, `s3:*`) | Data Perimeter | `HIGH` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`IAM_15`** | Security Defense Evasion (CloudTrail/GuardDuty/KMS tampering) | Resource Protection | `CRITICAL` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`IAM_16`** | Unrestricted KMS Decryption (`kms:Decrypt`, `kms:*`) | Data Perimeter | `HIGH` | ✅ Implemented | Attach Permissions Boundary (`nhi-permissions-boundary`) |
| **`TAG_01`** | Missing Mandatory Governance Tags (`Owner`, `Environment`) | Governance & Tagging | `LOW` | ✅ Implemented | Apply Mandatory Tags |

**Detection methodology sources:** Rules are informed by Rhino Security Labs' documented AWS IAM privilege escalation research (21 methods), Salesforce's Cloudsplaining policy-severity methodology, the CIS AWS Foundations Benchmark (credential hygiene thresholds), and AWS's own IAM best-practices documentation.

### Example Security Finding

```json
{
  "RuleID": "IAM_03",
  "IdentityType": "User",
  "IdentityName": "pam-suite-admin",
  "PolicyName": "IAMFullAccess",
  "Action": "iam:*",
  "Finding": "Administrator-Equivalent Permissions",
  "Resource": "*",
  "Severity": "CRITICAL"
}
```

---

## 🔒 Containment Strategy: Why Permissions Boundaries?

Rather than performing destructive and risky surgical policy rewrites in real time (which can break legitimate production applications), automated policy remediation uses **Permissions Boundary Containment**:

* **Baseline Ceiling (`Allow *`):** Leaves routine operational read/write actions untouched so services do not crash.
* **Hard Deny Guardrails:** Explicitly denies dangerous escalation actions (`iam:PutUserPermissionsBoundary`, `iam:DeleteRolePermissionsBoundary`, `iam:DeleteUserPermissionsBoundary`, `iam:PassRole`, `iam:CreatePolicyVersion`, etc.) so the identity cannot strip its own boundary ceiling or escalate permissions.
* **Non-Destructive Key Deactivation:** Stale and unused keys are toggled to `Inactive` rather than deleted, providing instant emergency rollback capabilities.
* **Exemption Management:** Protected identities (break-glass roles, runner identities) are defined in `nhi-ignore.yaml` and skipped automatically.

---

## ⚙️ Configuring Exemptions (`nhi-ignore.yaml`)

Automated containment checks findings against `nhi-ignore.yaml` before executing actions. Define your critical infrastructure identities to prevent automated containment:

```yaml
version: "1.0"
exemptions:
  # 1. CORE ADMINISTRATOR & PIPELINE USERS
  users:
    - name: "pam-suite-admin"
      reason: "Emergency break-glass administrator; exempt from automated boundaries"
      rules: ["*"]

    - name: "terraform"
      reason: "Terraform deployment user; requires full resource provisioning access"
      rules: ["*"]

    - name: "nhi-automation-runner-dev"
      reason: "Execution identity for NHI scanner; must avoid self-containment"
      rules: ["*"]

  # 2. AUTOMATION & AWS SERVICE-LINKED ROLES
  roles:
    - name: "nhi-automation-runner-role-dev"
      reason: "Execution role for inventory collection, S3 export, and remediation dispatcher"
      rules: ["*"]

    - name: "AWSServiceRoleForAccessAnalyzer"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

    - name: "AWSServiceRoleForResourceExplorer"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

    - name: "AWSServiceRoleForSupport"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

    - name: "AWSServiceRoleForTrustedAdvisor"
      reason: "AWS Service-Linked Role"
      rules: ["*"]

  # 3. IAM GROUPS (Permissions boundaries not supported on IAM groups by AWS)
  groups:
    - name: "test-group"
      reason: "IAM groups do not support Permissions Boundaries in AWS IAM APIs"
      rules: ["*"]
```

* **Exempt All Rules:** `rules: ["*"]`
* **Exempt Specific Rules:** `rules: ["IAM_01", "IAM_03"]` (allows credential hygiene deactivations `IAM_11`/`IAM_12` while skipping policy boundaries).

---

## 🔌 Extending Detection & Remediation

The architecture decouples offline rule evaluation from remediation dispatching, making it straightforward to plug in new risk rules and containment handlers.

### 1. Adding a New Privilege Escalation / Risk Rule
1. Create or update a rule file in `nhi/risk/rules/` (e.g., `privilege_escalation.py`).
2. Define the detector returning standard finding payloads (`RuleID`, `IdentityType`, `IdentityName`, `Severity`, `Finding`).
3. Register the rule call inside `nhi/risk/risk.py`.

### 2. Adding a Targeted Remediation Handler
1. Create a handler function inside `nhi/remediation/handlers/` with the signature:
   ```python
   def handle_custom_remediation(finding: dict, dry_run: bool = True) -> bool:
       # Return True on success / simulated success, False on failure
   ```
2. Map the corresponding `RuleID` to the new handler in `nhi/remediation/dispatch.py`:
   ```python
   HANDLER_MAP = {
       ...
       "IAM_09": handle_custom_remediation,
   }
   ```
3. Add unit tests with mock injections under `tests/`.

---

## 🔮 Target Expansion Vectors (Roadmap)

### Planned Privilege Escalation Rules (Rhino Security Taxonomy)
* **`iam:UpdateAssumeRolePolicy`**: Modify existing role trust policies to allow self-assumption.
* **`iam:AttachGroupPolicy` / `iam:AddUserToGroup`**: Escalate privileges via high-privilege IAM group membership.
* **`lambda:UpdateFunctionCode` / `lambda:CreateFunction` + `iam:PassRole`**: Serverless execution role abuse.
* **`glue:CreateDevEndpoint` / `glue:UpdateDevEndpoint`**: Escalation via AWS Glue developer service roles.
* **`cloudformation:CreateStack`**: CloudFormation template execution role privilege escalation.

### Planned Remediation Modes
* **Surgical Policy Stripping (Phase 5):** Parse inline JSON policy documents and rewrite wildcard statements (`*`) to explicit, least-privilege action lists without attaching boundary ceilings.
* **Direct Admin Policy Detachment:** Programmatically detach AWS-managed root policies (`AdministratorAccess`) for unexempted machine roles.
* **Automated Rollback Ledger:** Record remediation actions to an S3-backed rollback journal allowing instant, one-click state reversion.

---

## 🗺️ Project Roadmap

### Completed Milestones

* [x] **Phase 1: AWS Infrastructure Foundation**
  * Infrastructure as Code via Terraform (`terraform/`)
  * Least-privilege IAM architecture and assume-role execution
  * Secure remote S3 state backend with encryption & versioning

* [x] **Phase 2: Discovery Engine & Ingestion**
  * IAM Users, Groups, Roles, Managed Policies & Inline Policies discovery
  * Access Key metadata enrichment (`GetAccessKeyLastUsed`)
  * Session caching for Boto3 API pagination
  * Snapshot export to local `inventory.json` and remote S3

* [x] **Phase 3: Risk Evaluation Engine**
  * Modular security rules (`wildcards.py`, `credentials.py`, `privilege_escalation.py`, `data_perimeter.py`, `resource_protection.py`, `tags.py`, `trust_policy.py`)
  * Detection for wildcard actions/resources, admin access, stale keys, unused/dormant keys, documented IAM privilege escalation paths, public trust policies, S3 data exfiltration, KMS decryption, and security defense evasion

* [x] **Phase 4: Automated Remediation Engine (Containment V1)**
  * Permissions Boundary containment for privilege escalation and policy over-privilege (`nhi/remediation/handlers/policy.py`)
  * Non-destructive access key deactivation (`nhi/remediation/handlers/credential.py`)
  * Dispatch pipeline with `dry_run` simulation and `nhi-ignore.yaml` exemptions (`nhi/remediation/dispatch.py`)
  * Run-over-run diffing engine with S3-backed state persistence (`nhi/remediation/diff.py`)
  * Standalone CLI packaging via `pyproject.toml` (`nhi` command) with custom `--csv` and OASIS SARIF v2.1.0 (`--sarif`) report exports
  * 100% offline unit test suite with `pytest` (`tests/test_remediation.py`, `tests/test_diff.py`, `tests/test_sarif.py`)

---

### 🔮 Future Architectural Planning

#### Phase 5: Risk Engine V2 & 3-Tier Remediation
* **Tier 3 Policy Surgery:**
  * Implement automated AST document rewrites via `policy_surgery.py` for inline policies.
  * Statement partitioning: Separate non-resource discovery APIs (`Describe*`, `List*`) from scoped resource mutations (`Put*`, `Get*`, `Decrypt`).
  * Rollback journaling: Save the pre-surgery policy JSON snapshot to S3 before executing `PutUserPolicy` / `PutRolePolicy` updates.
* **Direct AdministratorAccess Detachment:** Dedicated handler for `IAM_03` to cleanly detach root-equivalent managed policies.
* **Target-Level Remediation Deduplication:** Coalesce multi-finding dispatches to execute single, unified remediation calls per IAM identity.

#### Phase 6: Team Communication & Event Notifications

* **Slack & Microsoft Teams Webhooks:** High/Critical findings pushed to dedicated SecOps channels with interactive "Acknowledge" or "Remediate" buttons.
* **Jira / ITSM Ticket Automation:** Automatic ticket generation for identified high-severity policy wildcards or dormant keys, assigning tasks directly to resource owner teams.
* **Event-Driven Architecture (AWS EventBridge / Lambda):** Trigger scans automatically upon IAM creation events (`CreateUser`, `CreateAccessKey`, `PutRolePolicy`). At this point the automation runner's authentication moves off static keys entirely — GitHub Actions via OIDC federation for CI/CD triggers, and a Lambda execution role directly as the trust-policy principal.

---

## ⚙️ Environment & Execution Setup

> **⚠️ Local development note:** the setup below uses a static IAM access key for the runner identity, sourced via `admin.sh`/`runner.sh`. This is a **temporary, local-dev-only pattern** — the runner's own Terraform-managed IAM user only holds `sts:AssumeRole` permission (see `terraform/main.tf`), with all actual scan/export/remediation permissions living on the assumed role, not the user. The static key exists solely to bootstrap that first `AssumeRole` call during local development and is not intended to ship in any deployed or public-facing version of this project. Planned replacements: **AWS IAM Identity Center (SSO)** for local/human use, and **GitHub OIDC federation** for the CI/CD `nhi-action` (Phase 6) — both eliminate the static key entirely by authenticating the caller directly and issuing short-lived credentials.

The scanner relies on environment variables set up via shell scripts (`admin.sh` and `runner.sh`) to extract Terraform outputs and configure execution session credentials.

### 1. Admin Credentials Script (`admin.sh`)

Create `admin.sh` (not committed — add to `.gitignore`) to export initial administrator credentials required for Terraform provisioning and bootstrap operations:

```bash
export AWS_ACCESS_KEY_ID="<YOUR_ADMIN_ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<YOUR_ADMIN_SECRET_KEY>"
```

### 2. Runner Setup Script (`runner.sh`)

The project uses `runner.sh` to extract provisioned IAM runner credentials, assumed role ARN, permissions boundary ARN, and S3 bucket names from Terraform outputs:

```bash
CURRENT_DIR=$(pwd)

cd terraform || exit

NHI_ACCESS_KEY_ID=$(terraform output -raw nhi_automation_runner_access_key_id)
NHI_SECRET_ACCESS_KEY=$(terraform output -raw nhi_automation_runner_secret_access_key)
ROLE_ARN=$(terraform output -raw nhi_automation_runner_role_arn)
export ROLE_ARN="$ROLE_ARN"
export NHI_BOUNDARY_POLICY_ARN=$(terraform output -raw permissions_boundary_policy_arn)

export AWS_ACCESS_KEY_ID="$NHI_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$NHI_SECRET_ACCESS_KEY"

export ROLE_NAME=nhi-automation-runner-role-dev
export BUCKET_NAME=pam-infrastructure-automation-suite-dev-bucket

cd "$CURRENT_DIR"
```

---

## 🔐 Required IAM Permissions

The scanner execution role requires the following minimal IAM policy to inventory IAM resources, upload snapshots, and apply containment boundaries/key deactivations:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMInventoryReadAccess",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListGroups",
        "iam:ListPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMRemediationAccess",
      "Effect": "Allow",
      "Action": [
        "iam:PutUserPermissionsBoundary",
        "iam:PutRolePermissionsBoundary",
        "iam:UpdateAccessKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3InventoryExportAccess",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::pam-infrastructure-automation-suite-dev-bucket/*"
    }
  ]
}
```

> **Note:** most of the `iam:List*`/`iam:Get*` actions above can be consolidated into a single `iam:GetAccountAuthorizationDetails` call, which returns users, groups, roles, and all attached/inline policy documents in one response. `ListAccessKeys` and `GetAccessKeyLastUsed` are not covered by that call and stay separate. This consolidation is a planned simplification, tracked for a future update — the granular list above reflects the current `terraform/main.tf`.

---

## 📂 Repository Structure

```text
nhi-risk-analyzer/
├── .github/
│   └── workflows/
│       └── nhi-scan.yml           # Automated CI/CD security scan via AWS OIDC & SARIF
├── nhi/
│   ├── aws/                       # Boto3 wrappers & session management
│   │   ├── iam.py                 # IAM API helpers
│   │   ├── s3.py                  # S3 upload & retrieval utilities
│   │   └── session.py             # Dual-mode (OIDC ambient + STS assume) session logic
│   ├── remediation/               # Automated remediation & diffing engine
│   │   ├── dispatch.py            # Handler routing & stats collection
│   │   ├── diff.py                # Posture drift & diffing logic
│   │   ├── config.py              # Exemption parser for nhi-ignore.yaml
│   │   └── handlers/              # Boundary & deactivation logic
│   ├── risk/                      # Core evaluation logic
│   │   ├── risk.py                # Main CLI runner & entry point
│   │   ├── helpers.py             # Classification utilities
│   │   └── rules/                 # IAM risk detection modules
│   ├── services/                  
│   │   ├── export.py              # JSON and CSV output handlers
│   │   ├── inventory.py           # State collection via Boto3
│   │   └── sarif.py               # OASIS SARIF v2.1.0 report generator
│   └── config.py                  # Global threshold configurations
├── terraform/                     # Infrastructure as Code
│   ├── oidc.tf                    # AWS OIDC Provider & GitHub Actions IAM role
│   ├── main.tf                    # Runner role, baseline policies, boundary definition
│   ├── outputs.tf                 # Exported ARNs (including oidc_role_arn)
│   ├── canary.tf                  # Canary IAM entities for detection validation
│   └── remote_state.tf            # S3 remote backend & state locking
├── tests/                         # Pytest unit testing suite
├── .gitignore                     # Untracked files configuration
├── admin.sh                       # Local admin bootstrap (gitignored)
├── automation_test.py             # Local testing and automation script
├── license.md                     # AGPLv3 License
├── nhi-ignore.yaml                # Remediation exemption list
├── pyproject.toml                 # Package configuration & CLI entry point
├── pytest.ini                     # Pytest environment config
├── README.md                      # Project documentation
└── runner.sh                      # Local session setup script (gitignored)
```

---

## 🚀 Quick Start Guide

### Prerequisites

* Python 3.10+
* Terraform 1.5+
* AWS CLI configured

### 1. Clone & Setup Virtual Environment

```bash
git clone https://github.com/likithmanoj/nhi-risk-analyzer.git
cd nhi-risk-analyzer

python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and package CLI in editable mode
pip install -e .
```

### 2. Bootstrap the Remote State Backend (first-time setup only)

The S3 bucket that stores Terraform's remote state is itself a Terraform-managed resource (`terraform/remote_state.tf`), which means it can't be its own backend on the very first apply. This was solved in two passes:

```bash
source admin.sh
cd terraform
```

**Pass 1 — create the backend bucket while still using local state:**

```bash
terraform init
terraform apply
```

At this stage `remote_state.tf`'s resources (bucket, versioning, encryption, public access block) are created, and Terraform is still tracking state locally (`terraform.tfstate` in the working directory) — the backend configuration hasn't been added to the config yet.

**Pass 2 — add the backend block and migrate:**

Once the bucket exists, add the `backend "s3" {...}` block (pointing at the bucket from Pass 1) to your Terraform configuration, then re-initialize:

```bash
terraform init
```

Terraform detects the existing local state file and prompts:

```text
Do you want to copy existing state to the new backend?
```

Answering `yes` copies the local `terraform.tfstate` into the S3 backend. From this point on, Terraform reads and writes remote state instead of the local file.

> **Provider version conflict during migration:** if the remote state was created with a newer AWS provider version than your local config is constrained to (e.g. state written with provider `6.x`, local config pinned to `~> 5.0`), migration can fail with `Resource instance managed by newer provider version` — the older provider can't decode state written by a newer provider's schema. Fix by updating `required_providers` to match the newer version:
>
> ```hcl
> required_providers {
>   aws = {
>     source  = "hashicorp/aws"
>     version = "~> 6.0"
>   }
> }
> ```
>
> then clear the local provider cache and lock file before reinitializing:
>
> ```bash
> rm -rf .terraform
> rm .terraform.lock.hcl
> terraform init
> ```

**Verify the migration succeeded:**

```bash
terraform validate      # expect: Success! The configuration is valid.
terraform plan           # expect: No changes. Your infrastructure matches the configuration.
terraform state list      # confirms resources are enumerable from the remote backend
terraform state pull      # confirms state is retrievable from the S3 backend

cd ..
```

Skip this whole bootstrap on subsequent clones/machines once the backend is already configured in the repo — `terraform init` alone will pull the existing remote state.

### 3. Provision Infrastructure via Terraform

```bash
source admin.sh
cd terraform
terraform apply -auto-approve
cd ..
```

### 4. Source Credentials & Execute Discovery / Risk Analysis

The execution engine provides three distinct run modes via CLI flags:

```bash
# Source dynamically generated runner credentials and boundary ARN
source runner.sh

# 1. Pure Scan & Run-over-Run Diff (Calculates posture drift and persists snapshot to S3)
nhi

# 2. Export Findings to CSV for spreadsheet review and auditing
nhi --csv findings.csv

# 3. Dry-Run Simulation Mode (Simulates containment and checks nhi-ignore.yaml exemptions)
nhi --dry-run

# 4. Dry-Run with CSV export in one command
nhi --dry-run --csv simulation_report.csv

# 5. Export findings to OASIS SARIF v2.1.0 for GitHub Code Scanning / CI/CD
nhi --sarif results.sarif

# 6. Combined Dry-Run simulation with SARIF export
nhi --dry-run --sarif security-scan.sarif

# 7. Live Containment Mode (Attaches Permissions Boundaries & deactivates stale keys)
nhi --remediate
```

---

## 🚀 CI/CD & GitHub Actions Integration (Keyless via AWS OIDC)

`nhi-risk-analyzer` runs natively inside GitHub Actions with **zero long-lived AWS access keys** by combining **AWS OpenID Connect (OIDC)** identity federation with **OASIS SARIF v2.1.0** security reporting.

```text
  ┌──────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
  │  GitHub Actions CI   │  OIDC   │   AWS STS Service  │ Assume  │   NHI Assessment   │
  │  (.github/workflows) │ ──────> │  (Trust Policy)    │ ──────> │   (OIDC-Assumed    │
  │  Mints Signed JWT    │         │  Validates Claims  │  Role   │    Permissions)    │
  └──────────────────────┘         └────────────────────┘         └────────────────────┘
             │                                                               │
             │                                                               │
             ▼                                                               ▼
  ┌──────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
  │ GitHub Security Tab  │ <────── │ upload-sarif@v3    │ <────── │  `results.sarif`   │
  │ Code Scanning Alerts │  SARIF  │ Ingests Findings   │ Output  │  OASIS v2.1.0 JSON │
  └──────────────────────┘         └────────────────────┘         └────────────────────┘
```

### Step 1: Provision OIDC Trust in Your AWS Account
Deploy the provided Terraform configuration in `terraform/oidc.tf` into your target AWS account. 

In `terraform/oidc.tf`, update the `sub` claim condition to trust your own GitHub organization and repository:

```hcl
condition {
  test     = "StringLike"
  values   = ["repo:<YOUR_GITHUB_ORG>/<YOUR_REPO>:*"]
  variable = "token.actions.githubusercontent.com:sub"
}
```

Deploy the infrastructure:
```bash
cd terraform
terraform init
terraform apply
```

Terraform automatically displays the created role ARN in the outputs at the end of the apply. You can also view it at any time:

* **From the repository root:**
  ```bash
  terraform -chdir=terraform output oidc_role_arn
  ```
* **From inside the `terraform/` directory:**
  ```bash
  terraform output oidc_role_arn
  ```

### Step 2: Configure Your GitHub Repository Variable
Set the repository variable via the GitHub CLI (`gh`):

```bash
gh variable set AWS_ROLE_TO_ASSUME --body "arn:aws:iam::<YOUR_ACCOUNT_ID>:role/oidc-role"
```

*(Alternatively, configure it via the GitHub UI under **Settings → Secrets and variables → Actions → Variables → New repository variable**).*

### Step 3: Add the GitHub Actions Workflow
Create `.github/workflows/nhi-scan.yml` in your repository:

```yaml
name: NHI Security Scan & SARIF Export

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  id-token: write        # Required for AWS OIDC authentication
  contents: read         # Required for actions/checkout to pull your repository
  security-events: write # Required for GitHub Code Scanning to ingest SARIF

jobs:
  scan:
    name: Run NHI Risk Assessment
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Configure AWS Credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_TO_ASSUME }}
          aws-region: us-east-1

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e .

      - name: Run NHI Scan
        run: |
          nhi --sarif results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: nhi-risk-analyzer
```

### Step 4: View Findings in GitHub Code Scanning
Once the workflow finishes, all security alerts (Privilege Escalation, Permissive Trust Policies, Credential Hygiene, Data Perimeter breaches) appear directly inside your GitHub repository under **Security → Code scanning alerts** with full rule IDs, severity indicators, and remediation guidance.

---

## 🧪 Running Unit Tests

To run the full unit test suite offline without live AWS API dependencies:

```bash
pytest tests/ -v
```

---

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)** - see the [LICENSE](license.md) file for details. Under AGPLv3, any modifications or network services (SaaS) built using this software must also make their complete source code publicly available under the same license terms.