data "aws_iam_policy_document" "devops" {
  statement {
    effect  = "Allow"
    actions = [
      "sts:AssumeRole"
    ]

    resources = [
      aws_iam_role.devops.arn
    ]
  }
}

resource "aws_iam_group" "devops" {
  name = "DevOps"
}

resource "aws_iam_group_policy" "devops" {
  name   = "DevOps"
  group  = aws_iam_group.devops.id
  policy = data.aws_iam_policy_document.devops.json
}
