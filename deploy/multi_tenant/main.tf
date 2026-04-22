terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  required_apis = [
    "securitycenter.googleapis.com",
    "securitycentermanagement.googleapis.com",
    "logging.googleapis.com",
    "bigquery.googleapis.com",
    "bigqueryconnection.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "aiplatform.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.required_apis)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "mcp_boss" {
  location      = var.region
  repository_id = var.image_repo
  format        = "DOCKER"
  description   = "MCP Boss container images"
  depends_on    = [google_project_service.apis]
}

locals {
  # Create one Secret Manager secret per non-empty sensitive value.
  # Keys with empty values are skipped entirely (the installer populates them later).
  active_secrets = {
    for k, v in var.sensitive_secrets : k => v if v != ""
  }
  # Secret name convention: mcp-boss-<lowercased-hyphened-key>
  secret_name = {
    for k, _ in var.sensitive_secrets :
    k => "mcp-boss-${replace(lower(k), "_", "-")}"
  }
}

resource "google_secret_manager_secret" "credentials" {
  for_each  = local.active_secrets
  project   = var.project_id
  secret_id = local.secret_name[each.key]
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "credentials" {
  for_each    = local.active_secrets
  secret      = google_secret_manager_secret.credentials[each.key].id
  secret_data = each.value
}

resource "google_secret_manager_secret_iam_member" "sa_accessor" {
  for_each  = local.active_secrets
  project   = var.project_id
  secret_id = google_secret_manager_secret.credentials[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.compute_sa_email}"
}

# Cloud Run service. The installer must build and push the image to the
# Artifact Registry repo before the service becomes healthy.
resource "google_cloud_run_v2_service" "mcp_boss" {
  name     = var.service_name
  location = var.region
  template {
    service_account = local.compute_sa_email
    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.image_repo}/mcp-boss:latest"
      env {
        name  = "SECOPS_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "SECOPS_CUSTOMER_ID"
        value = var.secops_customer_id
      }
      env {
        name  = "SECOPS_REGION"
        value = var.secops_region
      }
      env {
        name  = "GOOGLE_CHAT_WEBHOOK_URL"
        value = var.google_chat_webhook_url
      }
      env {
        name  = "APPROVAL_WEBHOOK_URL"
        value = var.approval_webhook_url
      }
      env {
        name  = "MCP_BOSS_AUDIT_PATH"
        value = var.audit_path
      }

      dynamic "env" {
        for_each = local.active_secrets
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.credentials[env.key].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }
  depends_on = [
    google_artifact_registry_repository.mcp_boss,
    google_secret_manager_secret_iam_member.sa_accessor,
  ]
}

output "service_url" {
  value = google_cloud_run_v2_service.mcp_boss.uri
}

output "approvals_url" {
  value       = "${google_cloud_run_v2_service.mcp_boss.uri}/api/approvals"
  description = "Point Google Chat / webhook approvers at this URL"
}

output "image_uri" {
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.image_repo}/mcp-boss:latest"
  description = "Tag to build and push to"
}

output "created_secrets" {
  value       = [for k, _ in local.active_secrets : local.secret_name[k]]
  description = "Secret Manager secrets created for sensitive credentials"
}
