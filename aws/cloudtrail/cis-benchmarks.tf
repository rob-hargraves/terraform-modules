resource "aws_sns_topic" "cis_benchmarks" {
  count = "${length(var.cis_benchmark_alerts) != 0 ? 1 : 0}"

  name = "cis-benchmarks"
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count = "${contains(var.cis_benchmark_alerts, "unauthorized_api_calls") ? 1 : 0}"

  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"
  name           = "Unauthorized Api Calls"
  pattern        = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"

  metric_transformation {
    name      = "UnauthorizedApiCalls"
    namespace = "LogMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count = "${contains(var.cis_benchmark_alerts, "unauthorized_api_calls") ? 1 : 0}"

  alarm_actions       = ["${aws_sns_topic.cis_benchmarks.arn}"]
  alarm_description   = "CIS Benchmark: Unauthorized Api Calls"
  alarm_name          = "${var.account_name}-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "${aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation.0.name}"
  namespace           = "${aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation.0.namespace}"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
}
