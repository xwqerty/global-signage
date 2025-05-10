provider "aws" {
  region = "us-east-1" # TODO: Replace with your desired AWS region
}

resource "aws_cognito_user_pool" "app_user_pool" {
  name = "GlobalAdUserPool" # Name for your user pool

  # Configuration for how users can sign up and sign in
  # We will use alias_attributes to allow users to sign in with email or preferred_username.
  # Do NOT use username_attributes when alias_attributes is specified.
  alias_attributes       = ["email"]
  auto_verified_attributes = ["email"]                   # Automatically verify email upon confirmation

  # Password policy for users
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
    temporary_password_validity_days = 7
  }

  # Multi-Factor Authentication (MFA) configuration
  mfa_configuration = "OFF" # Can be "OFF", "ON", or "OPTIONAL"

  # Email configuration for sending verification codes, invitations, etc.
  # COGNITO_DEFAULT has sending limits. For production, configure SES using "DEVELOPER".
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
    # from_email_address      = "noreply@example.com" # Required if email_sending_account is DEVELOPER
    # source_arn              = "arn:aws:ses:REGION:ACCOUNT_ID:identity/example.com" # Required if email_sending_account is DEVELOPER
  }

  # Schema attributes define the information you store for users.
  # 'email' and 'preferred_username' are standard when used as aliases.
  schema {
    name                = "email"
    attribute_data_type = "String"
    mutable             = false # Email cannot be changed by the user after creation (can be true if desired)
    required            = true
    string_attribute_constraints {
      min_length = 5
      max_length = 2048
    }
  }



  # You can define other standard attributes if you want them to be explicitly part of your schema
  # and control their mutability or requirements, for example:
  # schema {
  #   name                = "name" # A common attribute from the 'profile' scope
  #   attribute_data_type = "String"
  #   mutable             = true
  #   required            = false
  # }
  # schema {
  #   name                = "picture"
  #   attribute_data_type = "String"
  #   mutable             = true
  #   required            = false
  # }


  # Configuration for user sign-up process
  admin_create_user_config {
    allow_admin_create_user_only = false # Set to false to allow users to sign themselves up
  }

  # Verification message template (optional customization)
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_message        = "Your verification code is {####}."
    email_subject        = "Verify your email for My App"
    sms_message          = "Your verification code is {####}."
  }

  tags = {
    Environment = "development"
    Project     = "GlobalAdSignage"
  }
}

resource "aws_cognito_user_pool_client" "app_client" {
  name         = "GlobalAdUserPoolWebClient" # Name for your app client
  user_pool_id = aws_cognito_user_pool.app_user_pool.id

  generate_secret = false # Set to true if your app is server-side and can protect the secret.
                         # For client-side (e.g., SPA) apps, this should be false.

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows = ["code", "implicit"]
  allowed_oauth_scopes = [
    "email",
    "openid", # Grants the ID token
    "profile", # Grants access to user's profile information (name, picture, etc.)
    "aws.cognito.signin.user.admin"
  ]

  callback_urls = ["http://localhost:3000/auth/cognito/callback"]
  logout_urls   = ["http://localhost:3000/login"]

  # Corrected read_attributes:
  # List specific attributes defined in your schema or standard attributes you want to read.
  # Standard attributes available: address, birthdate, email, email_verified, family_name, gender, given_name,
  # locale, middle_name, name, nickname, phone_number, phone_number_verified, picture, preferred_username,
  # profile (as a URL), updated_at, website, zoneinfo.
  # Ensure any custom attributes are defined in the user pool schema block.
  read_attributes = [
    "email",
    "email_verified",
    # If you added "name" or "picture" to your schema above, you can add them here:
    # "name",
    # "picture",
    # Add other standard attributes you need, e.g.:
    "updated_at",
    "given_name",
    "family_name"
  ]

  # Corrected write_attributes:
  # List only attributes that are defined in your schema AND are mutable.
  write_attributes = []

  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH"
  ]

  prevent_user_existence_errors = "ENABLED"
  supported_identity_providers = ["COGNITO"]
}

# (Optional) User pool domain - required for Cognito Hosted UI
# resource "aws_cognito_user_pool_domain" "app_domain" {
#   domain       = "my-unique-app-domain-prefix" # TODO: Choose a globally unique domain prefix
#   user_pool_id = aws_cognito_user_pool.app_user_pool.id
# }

# Outputs
output "cognito_user_pool_id" {
  description = "The ID of the Cognito User Pool."
  value       = aws_cognito_user_pool.app_user_pool.id
}

output "cognito_user_pool_arn" {
  description = "The ARN of the Cognito User Pool."
  value       = aws_cognito_user_pool.app_user_pool.arn
}

output "cognito_user_pool_client_id" {
  description = "The ID of the Cognito User Pool Client."
  value       = aws_cognito_user_pool_client.app_client.id
}

output "cognito_user_pool_client_secret" {
  description = "The Secret of the Cognito User Pool Client."
  value       = aws_cognito_user_pool_client.app_client.client_secret
  sensitive   = true
}

output "cognito_user_pool_endpoint" {
  description = "The endpoint for the Cognito User Pool (e.g., cognito-idp.REGION.amazonaws.com/USER_POOL_ID)."
  value       = aws_cognito_user_pool.app_user_pool.endpoint
}

# output "cognito_hosted_ui_domain" {
#   description = "The domain for the Cognito Hosted UI."
#   value       = aws_cognito_user_pool_domain.app_domain.domain
# }
