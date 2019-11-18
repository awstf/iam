provider "aws" {}

terraform {
  required_version = ">= 0.12"
  backend "s3" {
    workspace_key_prefix = ""
    key                  = "iam.tfstate"
  }
}

data "aws_caller_identity" "current" {}
