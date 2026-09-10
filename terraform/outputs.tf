output "nhi_automation_runner_arn" {
  value       = aws_iam_user.nhi_automation_runner.arn
  description = "The Amazon Resource Name (ARN) of the NHI Automation Runner IAM user"
}
output "nhi_automation_runner_access_key_id" {
  value       = aws_iam_access_key.nhi_runner_keys.id
  description = "The access key ID for the NHI Automation Runner IAM user"
}

output "nhi_automation_runner_secret_access_key" {
  value       = aws_iam_access_key.nhi_runner_keys.secret
  description = "The access secret for the NHI Automation Runner IAM user"
  sensitive   = true
}

output "nhi_automation_runner_role_arn" {
  value = aws_iam_role.nhi_automation_runner_role.arn
}
output "permissions_boundary_policy_arn" {
  description = "ARN of the NHI Permissions Boundary policy"
  value       = aws_iam_policy.permissions_boundary_policy.arn
}
output "oidc_role_arn" {
  description = "ARN of Oidc role"
  value       = aws_iam_role.oidc-role.arn
}
