variable "project_id" {
  description = "ID do projeto GCP"
  type        = string
  default     = "prototipo-puc"
}

variable "project_number" {
  description = "Número do projeto GCP"
  type        = string
  default     = "811890592302"
}

variable "region" {
  description = "Região GCP para cálculo de previsibilidade financeira"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zona GCP"
  type        = string
  default     = "us-central1-a"
}

variable "machine_type" {
  description = "Instância econômica em CPU para OTel Collector + Gemma 3 1B GGUF 4-bit"
  type        = string
  default     = "e2-standard-4"
}

variable "use_spot_vm" {
  description = "Usar Spot VM (~$0.0804/h) para reduzir custos do laboratório"
  type        = bool
  default     = true
}
