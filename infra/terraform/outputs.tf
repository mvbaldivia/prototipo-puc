output "project_id" {
  value = var.project_id
}

output "pubsub_ingest_topic" {
  value = google_pubsub_topic.telemetry_ingest.id
}

output "pubsub_dlq_topic" {
  value = google_pubsub_topic.telemetry_dlq.id
}

output "collector_service_account" {
  value = google_service_account.collector_sa.email
}

output "pipeline_vm_name" {
  value = google_compute_instance.pipeline_node.name
}
