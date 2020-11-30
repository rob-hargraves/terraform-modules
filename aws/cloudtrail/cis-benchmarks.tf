resource "aws_sns_topic" "cis_benchmarks" {
  count = "${length(var.cis_benchmark_alerts) != 0 ? 1 : 0}"

  name = "cis-benchmarks"
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count = "${contains(var.cis_benchmark_alerts, "unauthorized_api_calls") ? 1 : 0}"

  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"
  name           = "Unauthorized API Calls"
  pattern        = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count = "${contains(var.cis_benchmark_alerts, "unauthorized_api_calls") ? 1 : 0}"

  alarm_actions       = ["${aws_sns_topic.cis_benchmarks.arn}"]
  alarm_description   = "CIS Benchmark: Unauthorized API Calls"
  alarm_name          = "${var.account_name}-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "${aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation.0.name}"
  namespace           = "${aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation.0.namespace}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "console_signin_without_mfa" {
  count = "${contains(var.cis_benchmark_alerts, "console_signin_without_mfa") ? 1 : 0}"

  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"
  name           = "Console Signin Without MFA"
  pattern        = "{($.eventName=\"ConsoleLogin\") && ($.additionalEventData.MFAUsed !=\"Yes\")}"

  metric_transformation {
    name      = "ConsoleSigninWithoutMFA"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_without_mfa" {
  count = "${contains(var.cis_benchmark_alerts, "console_signin_without_mfa") ? 1 : 0}"

  alarm_actions       = ["${aws_sns_topic.cis_benchmarks.arn}"]
  alarm_description   = "CIS Benchmark: Console Signin Without MFA"
  alarm_name          = "${var.account_name}-console-signin-without-mfa"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "${aws_cloudwatch_log_metric_filter.console_signin_without_mfa.metric_transformation.0.name}"
  namespace           = "${aws_cloudwatch_log_metric_filter.console_signin_without_mfa.metric_transformation.0.namespace}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  count = "${contains(var.cis_benchmark_alerts, "root_account_usage") ? 1 : 0}"

  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"
  name           = "Root Account Usage"
  pattern        = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_account_usage" {
  count = "${contains(var.cis_benchmark_alerts, "root_account_usage") ? 1 : 0}"

  alarm_actions       = ["${aws_sns_topic.cis_benchmarks.arn}"]
  alarm_description   = "CIS Benchmark: Root Account Usage"
  alarm_name          = "${var.account_name}-root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "${aws_cloudwatch_log_metric_filter.root_account_usage.metric_transformation.0.name}"
  namespace           = "${aws_cloudwatch_log_metric_filter.root_account_usage.metric_transformation.0.namespace}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  count = "${contains(var.cis_benchmark_alerts, "iam_policy_changes") ? 1 : 0}"

  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"
  name           = "IAM Policy Changes"
  pattern        = "{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}"

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  count = "${contains(var.cis_benchmark_alerts, "iam_policy_changes") ? 1 : 0}"

  alarm_actions       = ["${aws_sns_topic.cis_benchmarks.arn}"]
  alarm_description   = "CIS Benchmark: IAM Policy Changes"
  alarm_name          = "${var.account_name}-iam-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "${aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation.0.name}"
  namespace           = "${aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation.0.namespace}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  count = "${contains(var.cis_benchmark_alerts, "cloudtrail_changes") ? 1 : 0}"

  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"
  name           = "CloudTrail Changes"
  pattern        = "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}"

  metric_transformation {
    name      = "CloudTrailChanges"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  count = "${contains(var.cis_benchmark_alerts, "cloudtrail_changes") ? 1 : 0}"

  alarm_actions       = ["${aws_sns_topic.cis_benchmarks.arn}"]
  alarm_description   = "CIS Benchmark: CloudTrail Changes"
  alarm_name          = "${var.account_name}-cloudtrail-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "${aws_cloudwatch_log_metric_filter.cloudtrail_changes.metric_transformation.0.name}"
  namespace           = "${aws_cloudwatch_log_metric_filter.cloudtrail_changes.metric_transformation.0.namespace}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "console_authentication_failure" {
  count = "${contains(var.cis_benchmark_alerts, "console_authentication_failure") ? 1 : 0}"

  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"
  name           = "Console Authentication Failure"
  pattern        = "{($.eventName=ConsoleLogin) && ($.errorMessage=\"Failed authentication\")}"

  metric_transformation {
    name      = "ConsoleAuthenticationFailure"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_authentication_failure" {
  count = "${contains(var.cis_benchmark_alerts, "console_authentication_failure") ? 1 : 0}"

  alarm_actions       = ["${aws_sns_topic.cis_benchmarks.arn}"]
  alarm_description   = "CIS Benchmark: Console Authentication Failure"
  alarm_name          = "${var.account_name}-console-authentication-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "${aws_cloudwatch_log_metric_filter.console_authentication_failure.metric_transformation.0.name}"
  namespace           = "${aws_cloudwatch_log_metric_filter.console_authentication_failure.metric_transformation.0.namespace}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"
}
