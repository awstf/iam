data "aws_iam_policy_document" "assume" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]

    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
  }
}

resource "aws_iam_role" "devops" {
  name               = "DevOps"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "devops-geo" {
  name   = "devops-geo"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.geo.json
}

resource "aws_iam_role_policy" "devops-net" {
  name   = "devops-net"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.net.json
}

resource "aws_iam_role_policy" "devops-ssh" {
  name   = "devops-ssh"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.ssh.json
}

resource "aws_iam_role_policy" "devops-ec2" {
  name   = "devops-ec2"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.ec2.json
}

resource "aws_iam_role_policy" "devops-iam" {
  name   = "devops-iam"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.iam.json
}

resource "aws_iam_role_policy" "devops-s3" {
  name   = "devops-s3"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.s3.json
}

resource "aws_iam_role_policy" "devops-rds" {
  name   = "devops-rds"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.rds.json
}

resource "aws_iam_role_policy" "devops-log" {
  name   = "devops-log"
  role   = aws_iam_role.devops.id
  policy = data.aws_iam_policy_document.log.json
}
