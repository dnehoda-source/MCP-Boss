locals {
  compute_sa_email = coalesce(
    var.compute_sa,
    "${data.google_project.target.number}-compute@developer.gserviceaccount.com"
  )

  required_roles = [
    "roles/chronicle.admin",
    "roles/securitycenter.findingsViewer",
    "roles/securitycenter.sourcesViewer",
    "roles/logging.viewer",
    "roles/logging.privateLogViewer",
    "roles/logging.logWriter",
    "roles/bigquery.dataViewer",
    "roles/bigquery.jobUser",
    "roles/aiplatform.user",
    "roles/artifactregistry.writer",
    "roles/iam.serviceAccountViewer",
    "roles/secretmanager.secretAccessor",
  ]
}

data "google_project" "target" {
  project_id = var.project_id
}

resource "google_project_iam_member" "sa_roles" {
  for_each = toset(local.required_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${local.compute_sa_email}"
}

output "service_account" {
  value = local.compute_sa_email
}
