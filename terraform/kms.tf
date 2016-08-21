provider "aws" {
    access_key = "${var.aws_access_key}"
    secret_key = "${var.aws_secret_key}"
    region = "${var.aws_region}"
}

variable "aws_access_key" {
  description = "AWS access key"
}

variable "aws_secret_key" {
  description = "AWS secret access key"
}

variable "aws_region" {
  description = "AWS region"
  default     = "eu-west-1"
}

resource "aws_kms_key" "cryptic_key" {
    description = "Cryptic secret store key"
}

output "kms_key_id" {
    value = "${aws_kms_key.cryptic_key.id}"
}