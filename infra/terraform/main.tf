# Rede privada isolada para o pipeline e SLM local
resource "google_compute_network" "pipeline_vpc" {
  name                    = "otel-ocsf-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "pipeline_subnet" {
  name          = "otel-ocsf-subnet"
  ip_cidr_range = "10.20.0.0/24"
  region        = var.region
  network       = google_compute_network.pipeline_vpc.id
}

# Bloqueia egress externo para manter o SLM em regime air-gapped em runtime
resource "google_compute_firewall" "deny_slm_egress" {
  name      = "deny-slm-external-egress"
  network   = google_compute_network.pipeline_vpc.name
  direction = "EGRESS"
  priority  = 1000

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["slm-airgapped"]
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
  name = "telemetry-ingest"
}

resource "google_pubsub_topic" "telemetry_dlq" {
  name = "telemetry-dlq"
}

resource "google_pubsub_subscription" "telemetry_ingest_sub" {
  name  = "telemetry-ingest-sub"
  topic = google_pubsub_topic.telemetry_ingest.id

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.telemetry_dlq.id
    max_delivery_attempts = 5
  }
}

# Service Account dedicada com princípio do menor privilégio (IAM)
resource "google_service_account" "collector_sa" {
  account_id   = "otel-ocsf-collector-sa"
  display_name = "OTel Collector & AI Resilience SA (Least Privilege)"
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
      size  = 30
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
    apt-get update && apt-get install -y docker.io docker-compose-v2
    systemctl enable --now docker
  EOF
}
