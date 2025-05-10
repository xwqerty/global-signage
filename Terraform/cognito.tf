terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" # Specify a recent version
    }
  }
}

provider "aws" {
  region = var.aws_region # Specify your desired AWS region
}

variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1" # Example: North Virginia
}

variable "user_pool_name" {
  description = "The name for the Cognito User Pool."
  type        = string
  default     = "GlobalAdPlatformUserPool"
}

variable "app_client_name" {
  description = "The name for the Cognito User Pool App Client."
  type        = string
  default     = "GlobalAdPlatformAppClient"
}

variable "supported_identity_providers" {
  description = "List of supported identity providers (e.g., COGNITO, Facebook, Google)."
  type        = list(string)
  default     = ["COGNITO"] # Default to Cognito's own user directory
}

resource "aws_cognito_user_pool" "ad_platform_user_pool" {
  name = var.user_pool_name

  # Password policy
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
    temporary_password_validity_days = 7
  }

  # Multi-Factor Authentication (MFA) - Optional, can be "OFF", "ON", or "OPTIONAL"
  mfa_configuration = "OPTIONAL" # Set to "ON" to enforce MFA
  sms_authentication_message = "Your authentication code is {####}." # Customize as needed
  software_token_mfa_configuration {
    enabled = true
  }

  # How users can sign up and sign in
  username_attributes = ["email"] # Users sign in with their email

  # Standard attributes
  schema {
    name                     = "email"
    attribute_data_type      = "String"
    mutable                  = false
    required                 = true
    developer_only_attribute = false
    string_attribute_constraints {
      min_length = 5
      max_length = 2048
    }
  }

  schema {
    name                     = "name"
    attribute_data_type      = "String"
    mutable                  = true
    required                 = true
    developer_only_attribute = false
    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  # Email verification settings
  auto_verified_attributes = ["email"] # Automatically verify email addresses

  verification_message_template {
    default_email_option  = "CONFIRM_WITH_CODE"
    email_message         = "Welcome to the Global Ad Platform! Your verification code is {####}."
    email_subject         = "Verify your email for Global Ad Platform"
    sms_message           = "Welcome to the Global Ad Platform! Your verification code is {####}."
  }

  # Lambda triggers (can be added later for custom workflows)
  # lambda_config {
  #   post_confirmation = aws_lambda_function.my_post_confirmation_lambda.arn
  # }

  tags = {
    Environment = "dev"
    Project     = "GlobalAdPlatform"
    ManagedBy   = "Terraform"
  }
}

resource "aws_cognito_user_pool_client" "ad_platform_app_client" {
  name         = var.app_client_name
  user_pool_id = aws_cognito_user_pool.ad_platform_user_pool.id

  # Authentication flows
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",             # Secure Remote Password protocol
    "ALLOW_REFRESH_TOKEN_AUTH",        # Allow refresh tokens
    "ALLOW_USER_PASSWORD_AUTH",        # For server-side auth if needed (use with caution)
    "ALLOW_ADMIN_USER_PASSWORD_AUTH"   # For admin operations
  ]

  generate_secret = false # For web/SPA clients, set to false. Set to true for confidential clients (server-side).

  # Token validity periods
  # The following two lines are commented out to rely on the AWS provider defaults (60 minutes for both)
  # due to an issue where explicitly setting '60' was misinterpreted as 60 hours.
  # access_token_validity  = 60 # minutes
  # id_token_validity      = 60 # minutes
  refresh_token_validity = 30 # days (This is in days and the numeric value is usually fine)

  supported_identity_providers = var.supported_identity_providers

  # Allowed OAuth flows and scopes (for federation, if you add social IdPs or an Authorization Server)
  # Note: If you enable these, you MUST provide valid callback_urls and logout_urls.
  # allowed_oauth_flows_user_pool_client = true
  # allowed_oauth_flows                  = ["code", "implicit"] # or just ["code"] for more secure server-side flow
  # allowed_oauth_scopes                 = ["phone", "email", "openid", "profile", "aws.cognito.signin.user.admin"]
  # callback_urls                        = ["http://localhost:3000/callback"] # Replace with your actual app's callback URL(s)
  # logout_urls                          = ["http://localhost:3000/logout"]   # Replace with your actual app's logout URL(s)

  prevent_user_existence_errors = "ENABLED" # Recommended for security

  depends_on = [aws_cognito_user_pool.ad_platform_user_pool]

  # The 'tags' block was removed from this resource as it's not supported here.
}

# Outputs
output "cognito_user_pool_id" {
  description = "The ID of the Cognito User Pool."
  value       = aws_cognito_user_pool.ad_platform_user_pool.id
}

output "cognito_user_pool_arn" {
  description = "The ARN of the Cognito User Pool."
  value       = aws_cognito_user_pool.ad_platform_user_pool.arn
}

output "cognito_user_pool_endpoint" {
  description = "The endpoint of the Cognito User Pool."
  value       = aws_cognito_user_pool.ad_platform_user_pool.endpoint
}

output "cognito_app_client_id" {
  description = "The ID of the Cognito User Pool App Client."
  value       = aws_cognito_user_pool_client.ad_platform_app_client.id
}

# output "cognito_app_client_secret" {
#   description = "The secret of the Cognito User Pool App Client (if generate_secret is true)."
#   value       = aws_cognito_user_pool_client.ad_platform_app_client.client_secret
#   sensitive   = true
# }