terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

resource "cloudflare_pages_project" "methodman" {
  account_id        = var.cloudflare_account_id
  name              = "methodman"
  production_branch = "main"

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_pages_project" "bugterium" {
  account_id        = var.cloudflare_account_id
  name              = "bugterium"
  production_branch = "main"

  lifecycle {
    prevent_destroy = true
  }
}

output "pages_url_methodman" {
  value       = "https://${cloudflare_pages_project.methodman.subdomain}"
  description = "Legacy Production URL"
}

output "pages_url" {
  value       = "https://${cloudflare_pages_project.bugterium.subdomain}"
  description = "Current Production URL"
}