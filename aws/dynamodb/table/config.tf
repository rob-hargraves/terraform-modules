resource "aws_dynamodb_table" "table" {
  attribute               = [
    "${var.attributes}"
  ]
  billing_mode            = "PAY_PER_REQUEST"
  global_secondary_index  = [
    "${var.global_secondary_indexes}"
  ]
  hash_key                = "${var.hash_key}"
  lifecycle {
    ignore_changes  = [
      "global_secondary_index.read_capacity",
      "global_secondary_index.write_capacity",
      "read_capacity",
      "ttl",
      "write_capacity"
    ]
    prevent_destroy = true
  }
  local_secondary_index   = [
    "${var.local_secondary_indexes}"
  ]
  name                    = "${var.name}"
  point_in_time_recovery {
    enabled = "${var.pitr_enabled}"
  }
  range_key               = "${var.range_key}"
  server_side_encryption {
    enabled = true
  }
  stream_enabled          = "${length(var.stream_view_type) > 0 ? true : false}"
  stream_view_type        = "${var.stream_view_type}"
  tags                    = "${local.tags}"
  ttl {
    attribute_name  = "${var.ttl_attribute_name}"
    enabled         = "${length(var.ttl_attribute_name) > 0 ? true : false}"
  }
}
