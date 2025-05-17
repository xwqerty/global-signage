provider "aws" {
  region = "us-east-1"  # Set to the same region as your Cognito User Pool
}

variable "bucket_name" {
  description = "The unique name for the S3 bucket"
  default     = "my-unique-bucket-name"  # Replace with your desired bucket name
}

# Create the S3 bucket
resource "aws_s3_bucket" "upload_bucket" {
  bucket = var.bucket_name
  acl    = "private"  # Ensures the bucket is not publicly accessible
}

# IAM policy to allow uploading (PutObject) to the S3 bucket
resource "aws_iam_policy" "s3_upload_policy" {
  name        = "s3-upload-policy"
  description = "Policy to allow uploading to the S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.upload_bucket.arn}/*"
      }
    ]
  })
}

# IAM role for EC2 instances to assume
resource "aws_iam_role" "ec2_role" {
  name = "ec2-s3-upload-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach the S3 upload policy to the IAM role
resource "aws_iam_role_policy_attachment" "attach_s3_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_upload_policy.arn
}

# IAM instance profile to associate the role with EC2 instances
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-s3-upload-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# Outputs
output "bucket_name" {
  description = "The name of the S3 bucket"
  value       = aws_s3_bucket.upload_bucket.bucket
}

output "role_arn" {
  description = "The ARN of the IAM role for EC2"
  value       = aws_iam_role.ec2_role.arn
}