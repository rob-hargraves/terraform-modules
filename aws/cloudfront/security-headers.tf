data "aws_iam_policy_document" "security_headers_assume_role" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    principals {
      identifiers = [
        "lambda.amazonaws.com",
        "edgelambda.amazonaws.com"
      ]
      type = "Service"
    }
  }
}

data "aws_iam_policy_document" "security_headers" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:*:*:*"
    ]
    sid       = "AllowLogCreation"
  }
}

resource "aws_iam_role" "security_headers" {
  assume_role_policy  = "${data.aws_iam_policy_document.security_headers_assume_role.json}"
  name                = "${var.distribution_name}-security-headers"
}

resource "aws_iam_role_policy" "security_headers" {
  name    = "${var.distribution_name}-security-headers"
  policy  = "${data.aws_iam_policy_document.security_headers.json}"
  role    = "${aws_iam_role.security_headers.id}"
}

resource "aws_lambda_function" "security_headers" {
  filename          = "${path.module}/security-headers/function.zip"
  function_name     = "${var.distribution_name}-security-headers"
  handler           = "function.handler"
  lifecycle {
    ignore_changes = [
      "filename"
    ]
  }
  publish           = true
  role              = "${aws_iam_role.security_headers.arn}"
  runtime           = "nodejs8.10"
  source_code_hash  = "${base64sha256(file("${path.module}/security-headers/function.zip"))}"
  tags              = "${local.tags}"
}

resource "aws_lambda_permission" "security_headers" {
  action        = "lambda:GetFunction"
  function_name = "${aws_lambda_function.security_headers.function_name}"
  principal     = "edgelambda.amazonaws.com"
  statement_id  = "AllowExecutionFromCloudFront"
}
