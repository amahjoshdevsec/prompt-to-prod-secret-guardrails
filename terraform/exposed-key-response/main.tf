# Layer 5 (stretch): automatic response when AWS detects a leaked access key.
# Terraform port (simplified, single Lambda) of aws-samples/notify-and-remediate-exposed-access-key,
# which uses CloudFormation + Step Functions.
#
# Flow: AWS Health risk event -> EventBridge -> Lambda:
#   1. deactivate the key   2. attach deny-all inline policy to the user
#   3. pull 24h of CloudTrail activity for that key   4. notify owner/SecOps via SNS
#
# Deploy in us-east-1 (IAM is global; Health risk events for IAM arrive there).
# Test only in a sandbox account.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "notify_email" {
  description = "Email to subscribe to the alert topic (confirm the subscription email)"
  type        = string
}

variable "auto_remediate" {
  description = "If false, only notify (useful for a first rollout)"
  type        = bool
  default     = true
}

resource "aws_sns_topic" "alerts" {
  name              = "exposed-key-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notify_email
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_iam_role" "lambda" {
  name = "exposed-key-responder"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# Least privilege: only what the responder needs.
resource "aws_iam_role_policy" "lambda" {
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["iam:GetAccessKeyLastUsed", "iam:UpdateAccessKey", "iam:PutUserPolicy"], Resource = "*" },
      { Effect = "Allow", Action = ["cloudtrail:LookupEvents"], Resource = "*" },
      { Effect = "Allow", Action = ["sns:Publish"], Resource = aws_sns_topic.alerts.arn },
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:*" },
    ]
  })
}

resource "aws_lambda_function" "responder" {
  function_name    = "exposed-key-responder"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 60
  environment {
    variables = {
      TOPIC_ARN      = aws_sns_topic.alerts.arn
      AUTO_REMEDIATE = tostring(var.auto_remediate)
    }
  }
}

resource "aws_cloudwatch_event_rule" "exposed_key" {
  name        = "aws-health-exposed-access-key"
  description = "AWS Health reports an IAM access key exposed publicly"
  event_pattern = jsonencode({
    source        = ["aws.health"]
    "detail-type" = ["AWS Health Event"]
    detail = {
      # Verify the code in your account: some reports show AWS_RISK_IAM_QUARANTINE instead.
      eventTypeCode = ["AWS_RISK_CREDENTIALS_EXPOSED", "AWS_RISK_IAM_QUARANTINE"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.exposed_key.name
  arn  = aws_lambda_function.responder.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.exposed_key.arn
}
