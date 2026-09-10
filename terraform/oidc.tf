resource "aws_iam_openid_connect_provider" "oidc-provider" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "oidc" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.oidc-provider.arn]
    }
    condition {
      test     = "StringEquals"
      values   = ["sts.amazonaws.com"]
      variable = "token.actions.githubusercontent.com:aud"
    }
    condition {
      test     = "StringLike"
      values   = ["repo:likithmanoj/nhi-risk-analyzer:*"] #Note to the users: Add your own Repo here for running the repo with OIDC for Github actions
      variable = "token.actions.githubusercontent.com:sub"
    }
  }
}
resource "aws_iam_role" "oidc-role" {
  name               = "oidc-role"
  assume_role_policy = data.aws_iam_policy_document.oidc.json
}
resource "aws_iam_role_policy_attachment" "oidc_role_attachment" {
  role       = aws_iam_role.oidc-role.name
  policy_arn = aws_iam_policy.role_policy.arn
}
