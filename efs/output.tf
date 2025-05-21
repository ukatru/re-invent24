output "access_points" {
  description = "Map of access points created and their attributes"
  value       = aws_efs_access_point.efs_access_point
}
