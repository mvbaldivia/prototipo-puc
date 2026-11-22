locals {
  required_apis = [
    "compute.googleapis.com",
    "pubsub.googleapis.com",
    "logging.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
  ]
}

# Habilita APIs necessárias no projeto prototipo-puc
resource "google_project_service" "services" {
  for_each           = toset(local.required_apis)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Repositório Artifact Registry para imagens do módulo ai-resilience (usado pelo Cloud Build)
resource "google_artifact_registry_repository" "tcc_repo" {
  location      = var.region
  repository_id = "tcc-repo"
  description   = "Repositório Docker do protótipo TCC PUCPR (OTel + OCSF + SLM)"
  format        = "DOCKER"
  depends_on    = [google_project_service.services]
}

# Rede privada isolada com Private Google Access (sem IP público externo)
resource "google_compute_network" "pipeline_vpc" {
  name                    = "otel-ocsf-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.services]
}

resource "google_compute_subnetwork" "pipeline_subnet" {
  name                     = "otel-ocsf-subnet"
  ip_cidr_range            = "10.20.0.0/24"
  region                   = var.region
  network                  = google_compute_network.pipeline_vpc.id
  private_ip_google_access = true
}

# Cloud Router + Cloud NAT para permitir pull das imagens Docker sem IP público na VM
resource "google_compute_router" "pipeline_router" {
  name    = "otel-ocsf-router"
  region  = var.region
  network = google_compute_network.pipeline_vpc.id
}

resource "google_compute_router_nat" "pipeline_nat" {
  name                               = "otel-ocsf-nat"
  router                             = google_compute_router.pipeline_router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# Permite SSH exclusivamente via Identity-Aware Proxy (IAP) para túnel ao Splunk (porta 8000)
resource "google_compute_firewall" "allow_iap_ssh" {
  name      = "allow-iap-ssh"
  network   = google_compute_network.pipeline_vpc.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["otel-collector"]
}

# Permite comunicação interna na sub-rede (OTel Collector <-> AI Resilience <-> SLM)
resource "google_compute_firewall" "allow_internal" {
  name    = "allow-pipeline-internal"
  network = google_compute_network.pipeline_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["4317", "4318", "11434"]
  }

  source_ranges = ["10.20.0.0/24"]
}

# Tópicos Pub/Sub: Ingestão e Quarentena (DLQ)
resource "google_pubsub_topic" "telemetry_ingest" {
  name       = "telemetry-ingest"
  depends_on = [google_project_service.services]
}

resource "google_pubsub_topic" "telemetry_dlq" {
  name       = "telemetry-dlq"
  depends_on = [google_project_service.services]
}

resource "google_pubsub_subscription" "telemetry_ingest_sub" {
  name  = "telemetry-ingest-sub"
  topic = google_pubsub_topic.telemetry_ingest.id

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.telemetry_dlq.id
    max_delivery_attempts = 5
  }
}

# Log Sink do Tenant GCP: envia Cloud Audit Logs reais para o Pub/Sub
resource "google_logging_project_sink" "audit_sink" {
  name        = "gcp-audit-to-otel-pubsub"
  project     = var.project_id
  destination = "pubsub.googleapis.com/${google_pubsub_topic.telemetry_ingest.id}"
  filter      = "log_id(\"cloudaudit.googleapis.com/activity\") OR log_id(\"cloudaudit.googleapis.com/data_access\")"

  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.telemetry_ingest.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.audit_sink.writer_identity
}

# Service Account dedicada com princípio do menor privilégio (IAM)
resource "google_service_account" "collector_sa" {
  account_id   = "otel-ocsf-collector-sa"
  display_name = "OTel Collector & AI Resilience SA (Least Privilege)"
  depends_on   = [google_project_service.services]
}

resource "google_pubsub_subscription_iam_member" "subscriber_perm" {
  subscription = google_pubsub_subscription.telemetry_ingest_sub.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.collector_sa.email}"
}

resource "google_pubsub_topic_iam_member" "dlq_publisher_perm" {
  topic  = google_pubsub_topic.telemetry_dlq.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.collector_sa.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.collector_sa.email}"
}

resource "google_artifact_registry_repository_iam_member" "artifact_reader" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.tcc_repo.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.collector_sa.email}"
}

# Service Account dedicada para CI/CD Deploy via Workload Identity Federation
resource "google_service_account" "github_deploy_sa" {
  account_id   = "github-deploy-sa"
  display_name = "GitHub Actions Deploy SA (CI/CD)"
  depends_on   = [google_project_service.services]
}

# Workload Identity Federation para GitHub Actions (CD sem chave JSON estática)
resource "google_iam_workload_identity_pool" "github_pool" {
  workload_identity_pool_id = "github-pool"
  display_name              = "GitHub Actions Pool"
  description               = "Pool de federação para CI/CD do repositório mvbaldivia/prototipo-puc"
  depends_on                = [google_project_service.services]
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub OIDC Provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "assertion.repository == \"mvbaldivia/prototipo-puc\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_wif_binding" {
  service_account_id = google_service_account.github_deploy_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/mvbaldivia/prototipo-puc"
}

resource "google_project_iam_member" "deploy_cloudbuild_editor" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.editor"
  member  = "serviceAccount:${google_service_account.github_deploy_sa.email}"
}

resource "google_project_iam_member" "deploy_artifact_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.github_deploy_sa.email}"
}

resource "google_project_iam_member" "deploy_storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.github_deploy_sa.email}"
}

resource "google_project_iam_member" "deploy_service_usage" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = "serviceAccount:${google_service_account.github_deploy_sa.email}"
}

resource "google_project_iam_member" "deploy_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.github_deploy_sa.email}"
}

# VM econômica (e2-standard-4) para OTel Collector + Gemma 3 1B (GGUF 4-bit)
resource "google_compute_instance" "pipeline_node" {
  name         = "otel-ocsf-slm-node"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["otel-collector", "slm-airgapped"]

  scheduling {
    preemptible                 = var.use_spot_vm
    automatic_restart           = var.use_spot_vm ? false : true
    provisioning_model          = var.use_spot_vm ? "SPOT" : "STANDARD"
    instance_termination_action = var.use_spot_vm ? "STOP" : null
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 50
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.pipeline_subnet.id
  }

  service_account {
    email  = google_service_account.collector_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -e
    apt-get update && apt-get install -y git curl
    if ! command -v docker >/dev/null 2>&1; then
      curl -fsSL https://get.docker.com | sh
      systemctl enable --now docker
    fi
    mkdir -p /opt/otel/data
    if [ ! -d /opt/otel/prototipo-puc/.git ]; then
      rm -rf /opt/otel/prototipo-puc
      git clone https://github.com/mvbaldivia/prototipo-puc.git /opt/otel/prototipo-puc || true
    fi
  EOF
}
