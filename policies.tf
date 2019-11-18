data "aws_iam_policy_document" "geo" {
  statement {
    actions = [
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeRegions",
    ]

    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "geo" {
  name        = "Geo"
  description = "Allows to list regions and availability zones."
  policy      = data.aws_iam_policy_document.geo.json
}

data "aws_iam_policy_document" "net" {
  statement {
    actions = [
      "ec2:*Tag*",

      "ec2:CreateVpc",
      "ec2:DeleteVpc",
      "ec2:ModifyVpcAttribute",
      "ec2:DescribeVpc*",

      "ec2:*DhcpOptions",
      "ec2:*FlowLogs",
      "ec2:*InternetGateway",
      "ec2:*NatGateway*",

      "ec2:CreateSubnet",
      "ec2:DeleteSubnet",
      "ec2:ModifySubnetAttribute",
      "ec2:DescribeSubnets",

      "ec2:AssociateRouteTable",
      "ec2:DisassociateRouteTable",

      "ec2:CreateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:DescribeRouteTables",

      "ec2:ReplaceRouteTableAssociation",

      "ec2:CreateRoute",
      "ec2:DeleteRoute",
      "ec2:ReplaceRoute",

      "ec2:AllocateAddress",
      "ec2:DescribeAddresses",
      "ec2:ReleaseAddress",
      "ec2:AssociateAddress",
      "ec2:DescribeAddresses",

      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupReferences",

      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
      "ec2:RevokeSecurityGroupEgress",

      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
      "ec2:RevokeSecurityGroupIngress",

      "ec2:AssociateSubnetCidrBlock",
      "ec2:DisassociateSubnetCidrBlock",

      "ec2:AssociateVpcCidrBlock",
      "ec2:DisassociateVpcCidrBlock",

      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:AttachNetworkInterface",
      "ec2:DetachNetworkInterface",
      "ec2:DescribeNetworkInterface*",

      "ec2:DescribePublicIpv4Pools",
      "ec2:DescribeNetworkAcls",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "elasticloadbalancing:*"
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "acm:RequestCertificate",
      "acm:DescribeCertificate",
      "acm:GetCertificate",
      "acm:ListCertificates",
      "acm:ListTagsForCertificate",
      "acm:DeleteCertificate",
      "acm:UpdateCertificateOptions",
    ]

    resources = [
      "*",
    ]
  }
}

resource "aws_iam_policy" "net" {
  name        = "NetworkAdministration"
  description = "Allows to perform basic VPC network management."
  policy      = data.aws_iam_policy_document.net.json
}

data "aws_iam_policy_document" "ec2" {
  statement {
    actions = [
      "ec2:*Tag*",

      "ec2:AssociateIamInstanceProfile",
      "ec2:DisassociateIamInstanceProfile",

      "ec2:DescribeIamInstanceProfileAssociations",
      "ec2:ReplaceIamInstanceProfileAssociation",

      "ec2:DescribeInstanceAttribute",
      "ec2:ModifyInstanceAttribute",

      "ec2:DescribeInstanceStatus",
      "ec2:DescribeInstances",

      "ec2:RunInstances",
      "ec2:StartInstances",
      "ec2:StopInstances",
      "ec2:TerminateInstances",

      "ec2:*Volume*",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "autoscaling:Create*",
      "autoscaling:AttachInstances",
      "autoscaling:DeleteAutoScalingGroup",
      "autoscaling:DeleteLaunchConfiguration",
      "autoscaling:DeleteTags",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeLoadBalancerTargetGroups",
      "autoscaling:DescribeLoadBalancers",
      "autoscaling:DescribePolicies",
      "autoscaling:DescribeTags",
      "autoscaling:DetachInstances",
      "autoscaling:EnableMetricsCollection",
      "autoscaling:DisableMetricsCollection",
      "autoscaling:UpdateAutoScalingGroup"
    ]

    resources = [
      "*",
    ]
  }
}

resource "aws_iam_policy" "ec2" {
  name        = "InstanceAdministration"
  description = "Allows to perform basic EC2 management."
  policy      = data.aws_iam_policy_document.ec2.json
}

data "aws_iam_policy_document" "ssh" {
  statement {
    actions = [
      "ec2-instance-connect:SendSSHPublicKey",
    ]

    resources = [
      "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:instance/*",
    ]
  }
}

resource "aws_iam_policy" "ssh" {
  name        = "SSHAccess"
  description = "Provides SSH access."
  policy      = data.aws_iam_policy_document.ssh.json
}

data "aws_iam_policy_document" "iam" {
  statement {
    actions = [
      "iam:CreatePolicy",
      "iam:DeletePolicy",
      "iam:CreateServiceLinkedRole",
      "iam:AddRoleToInstanceProfile",
      "iam:CreateInstanceProfile",
      "iam:DeleteInstanceProfile",
      "iam:GetRole",
      "iam:PassRole",
      "iam:CreateRole",
      "iam:UpdateRole",
      "iam:GetRolePolicy",
      "iam:ListInstanceProfiles",
      "iam:ListRoles",
      "iam:GetInstanceProfile",
      "iam:ListRolePolicies",
      "iam:DeleteRole",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:ListInstanceProfilesForRole",
      "iam:DeleteServiceLinkedRole",
      "iam:ListPolicyVersions",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListEntitiesForPolicy",
      "iam:ListAttachedRolePolicies",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:PutRolePolicy",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/c-*",
    ]
  }

  statement {
    actions = [
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/c-*",
    ]
  }
}

resource "aws_iam_policy" "iam" {
  name        = "ComputePermissions"
  description = "Provides permissions management for compute resources."
  policy      = data.aws_iam_policy_document.iam.json
}

data "aws_iam_policy_document" "s3" {
  statement {
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:DeleteBucketWebsite",
      "s3:GetBucketAcl",
      "s3:GetBucketCORS",
      "s3:GetBucketLocation",
      "s3:GetBucketLogging",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:GetBucketWebsite",
      "s3:GetAccelerateConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:GetBucketRequestPayment",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetEncryptionConfiguration",
      "s3:GetInventoryConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:ListBucket",
      "s3:ListAllMyBuckets",
      "s3:ListBucketVersions",
      "s3:PutBucketAcl",
      "s3:PutBucketCORS",
      "s3:PutBucketLogging",
      "s3:PutBucketPolicy",
      "s3:PutBucketTagging",
      "s3:PutBucketVersioning",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]

    resources = [
      "*",
    ]
  }
}

resource "aws_iam_policy" "s3" {
  name        = "BucketAdministration"
  description = "Allows to perform basic S3 administration."
  policy      = data.aws_iam_policy_document.s3.json
}

data "aws_iam_policy_document" "rds" {
  statement {
    actions = [
      "rds:*OptionGroup*",
      "rds:*DBParameterGroup*",
      "rds:*DBInstance*",
      "rds:AddTagsToResource",
      "rds:ApplyPendingMaintenanceAction",
      "rds:AuthorizeDBSecurityGroupIngress",
      "rds:CreateDBSecurityGroup",
      "rds:CreateDBSubnetGroup",
      "rds:DeleteDBSecurityGroup",
      "rds:DeleteDBSubnetGroup",
      "rds:DescribeCertificates",
      "rds:DescribeDBEngineVersions",
      "rds:DescribeDBLogFiles",
      "rds:DescribeDBParameters",
      "rds:DescribeDBSecurityGroups",
      "rds:DescribeDBSnapshots",
      "rds:DescribeDBSubnetGroups",
      "rds:DescribeEngineDefaultParameters",
      "rds:ListTagsForResource",
      "rds:ModifyDBSubnetGroup",
      "rds:RemoveTagsFromResource",
      "rds:RevokeDBSecurityGroupIngress",
    ]

    resources = [
      "*",
    ]
  }
}

resource "aws_iam_policy" "rds" {
  name        = "DatabaseAdministration"
  description = "Allows to perform basic RDS administration."
  policy      = data.aws_iam_policy_document.rds.json
}

data "aws_iam_policy_document" "ssm" {
  statement {
    actions = [
      "ssm:*Parameter*",
      "ssm:*TagsForResource",
    ]

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "log" {
  statement {
    actions = [
      "logs:*LogGroup*",
      "logs:*RetentionPolicy",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "cloudwatch:*TagsForResource",
    ]

    resources = [
      "*",
    ]
  }
}
