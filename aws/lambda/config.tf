data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    principals {
      identifiers = [
        "lambda.amazonaws.com"
      ]
      type = "Service"
    }
  }
}

resource "aws_iam_role" "function" {
  name = "${var.name}"
  assume_role_policy = "${data.aws_iam_policy_document.assume_role.json}"
}

resource "aws_cloudwatch_log_group" "log_group" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = 7
}

data "aws_iam_policy_document" "function" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "${aws_cloudwatch_log_group.log_group.arn}"
    ]
    sid       = "AllowLogWriting"
  }
  statement {
    actions   = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*"
    ]
    resources = [
      "${var.kms_key_arn}"
    ]
    sid       = "AllowEcryptDecryptEnvVars"
  }
  statement {
    actions   = [
      "sns:Publish",
      "sqs:SendMessage"
    ]
    resources = [
      "${var.dead_letter_arn}"
    ]
    sid       = "AllowDeadLetterWriting"
  }
}

resource "aws_iam_role_policy" "log_group_access" {
  name    = "log-group-access"
  policy  = "${data.aws_iam_policy_document.function.json}"
  role    = "${aws_iam_role.function.id}"
}

resource "aws_iam_role_policy_attachment" "managed_policy" {
  count       = "${var.policy_arns_count}"
  policy_arn  = "${var.policy_arns[count.index]}"
  role        = "${aws_iam_role.function.name}"
}

data "aws_s3_bucket_object" "function_package" {
  bucket      = "${var.s3_bucket}"
  key         = "${var.s3_object_key}"
}

resource "aws_lambda_function" "function" {
  dead_letter_config {
    target_arn = "${var.dead_letter_arn}"
  }
  depends_on = ["aws_cloudwatch_log_group.log_group"]
  environment {
    variables = "${var.environment_variables}"
  }
  function_name     = "${var.name}"
  handler           = "${var.handler}"
  kms_key_arn       = "${var.kms_key_arn}"
  memory_size       = "${var.memory_size}"
  publish           = true
  role              = "${aws_iam_role.function.arn}"
  runtime           = "${var.runtime}"
  s3_bucket         = "${data.aws_s3_bucket_object.function_package.bucket}"
  s3_key            = "${data.aws_s3_bucket_object.function_package.key}"
  s3_object_version = "${data.aws_s3_bucket_object.function_package.version_id}"
  timeout           = "${var.timeout}"
}
