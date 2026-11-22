# Protótipo TCC PUCPR Digital — Pipeline Autônomo Multi-Cloud (OTel + OCSF v1.9.0 + SLM)

Implementação de referência do artigo **"Pipeline Autônomo de Normalização Semântica de Telemetria Multi-Cloud Baseado em OpenTelemetry, OCSF e Small Language Models para Engenharia de Detecção"**.

- **Projeto GCP:** `prototipo-puc` (`811890592302`)
- **Esquema Alvo:** OCSF `v1.9.0` — Classe `API Activity (6003)`
- **SLM Local:** `Gemma 3 1B` (GGUF 4-bit, execução *air-gapped* em CPU)

## Estrutura

```text
prototype/
├── ai-resilience/          # Camada 3: Sanitizador, cliente SLM local e validador OCSF
│   └── schemas/            # Contrato JSON Schema OCSF v1.9.0 (6003)
├── otel-collector/         # Camada 2: OpenTelemetry Collector + regras OTTL
├── simulator/              # Camada 1: Gerador multi-cloud (AWS/Azure/GCP) + drift + ataques
├── tests/                  # Suíte pytest (regressão, OCSF, prompt injection e ACS)
├── infra/terraform/        # IaC GCP (VPC, Pub/Sub, IAM menor privilégio, VM e2-standard-4)
├── .github/workflows/      # Esteira CI/CD com gate human-in-the-loop
├── cloudbuild.yaml         # Deploy automatizado no GCP (prototipo-puc)
└── docker-compose.yml      # Execução local isolada (rede SLM internal: true)
```

## Execução Local (Custo Zero)

1. Instalar dependências e rodar os testes determinísticos, de regressão e de segurança:
   ```bash
   pip install -r requirements.txt
   pytest -v
   ```
2. Subir a stack completa localmente (OTel Collector + Ollama `gemma3:1b` em rede isolada + módulo de resiliência):
   ```bash
   docker compose up -d
   docker compose exec ollama ollama pull gemma3:1b
   ```

## Deploy no GCP (`prototipo-puc`)

1. Provisionar infraestrutura (VM `e2-standard-4` Spot, Pub/Sub, IAM e rede *air-gapped*):
   ```bash
   cd infra/terraform
   terraform init
   terraform plan
   terraform apply
   ```
2. Ao concluir os ensaios do laboratório, destruir os recursos para evitar cobrança contínua:
   ```bash
   terraform destroy
   ```
