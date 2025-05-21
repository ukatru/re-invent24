data "aws_vpc" "selected_vpc" {
  tags = {
    Name = var.vpc_name
  }
}