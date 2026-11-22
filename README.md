# Protótipo TCC PUCPR Digital — Pipeline Autônomo Multi-Cloud (OTel + OCSF v1.9.0 + SLM)

Implementação de referência do artigo **"Pipeline Autônomo de Normalização Semântica de Telemetria Multi-Cloud Baseado em OpenTelemetry, OCSF e Small Language Models para Engenharia de Detecção"**.

- **Projeto GCP:** `prototipo-puc` (`811890592302`)
- **Esquema Alvo:** OCSF `v1.9.0` — Classe `API Activity (6003)`
- **SLM Local:** `Gemma 3 1B` (GGUF 4-bit, execução *air-gapped* em CPU)
- **SIEM Local (Testes):** Splunk via HTTP Event Collector (HEC) na porta `8088`, índice `otel_ocsf`

---

## Estrutura do Projeto

```text
prototype/
├── ai-resilience/          # Camada 3: Sanitizador, cliente SLM local e validador OCSF
│   └── schemas/            # Contrato JSON Schema OCSF v1.9.0 (6003)
├── otel-collector/         # Camada 2: OpenTelemetry Collector + regras OTTL + Splunk HEC
├── simulator/              # Camada 1: Gerador multi-cloud (AWS/Azure/GCP) + drift + ataques
├── splunk/                 # Configuração local do Splunk (porta 8088 + índice otel_ocsf)
├── tests/                  # Suíte pytest (regressão, OCSF, prompt injection e ACS)
├── infra/terraform/        # IaC GCP (VPC, Pub/Sub, IAM menor privilégio, VM e2-standard-4)
├── .github/workflows/      # Esteira CI/CD com gate human-in-the-loop
├── cloudbuild.yaml         # Deploy automatizado no GCP (prototipo-puc)
├── .env.example            # Modelo de variáveis locais (sem segredos)
└── docker-compose.yml      # Execução local isolada (rede SLM internal: true)
```

---

## Passo a Passo Detalhado — Subida do Projeto Local (com Splunk)

### Passo 1: Configurar variáveis locais (sem expor segredos no Git)
Na pasta `prototype/`:
```powershell
Copy-Item .env.example .env
```
Edite o `.env` garantindo o endpoint e o token do seu Splunk HEC:
```ini
SPLUNK_HEC_ENDPOINT=https://host.docker.internal:8088/services/collector
SPLUNK_HEC_TOKEN=seu-token-hec-aqui
```
*(O arquivo `.env` está no `.gitignore` e nunca é enviado para o GitHub.)*

### Passo 2: Configurar/Subir o Splunk Local (porta `8088` aberta)
- **Se você já tem um `docker-compose` do Splunk:** adicione a porta `"8088:8088"` ao serviço do Splunk e reinicie o container:
  ```yaml
  ports:
    - "8000:8000"
    - "8088:8088"
    - "9997:9997"
  ```
  No Splunk Web (`http://localhost:8000`), confirme:
  1. **Settings $\rightarrow$ Indexes:** existe o índice `otel_ocsf`;
  2. **Settings $\rightarrow$ Data Inputs $\rightarrow$ HTTP Event Collector $\rightarrow$ Global Settings:** `All Tokens = Enabled` (e `Enable SSL` conforme seu `.env`: `https://` se marcado, `http://` se desmarcado).
- **Ou use a configuração pronta em `splunk/`:**
  ```powershell
  docker compose --env-file .env -f splunk/docker-compose.splunk.yml up -d
  ```

### Passo 3: Validar a suíte de testes determinísticos e segurança
```powershell
pip install -r requirements.txt
python -m pytest -v
```
Todos os testes (sanitização contra *prompt injection*, rejeição de campos desconhecidos e validação JSON Schema OCSF `v1.9.0`) devem passar (`4 passed`).

### Passo 4: Subir o Pipeline (OTel Collector + Ollama Gemma 3 1B + AI Resilience)
```powershell
docker compose up -d
docker compose exec ollama ollama pull gemma3:1b
```
Verifique os containers em execução:
```powershell
docker compose ps
```

### Passo 5: Enviar evento de teste e validar no Splunk (`index="otel_ocsf"`)
1. Envie um payload OTLP de teste (formato AWS CloudTrail) para o OTel Collector na porta `4318`:
   ```powershell
   curl -X POST http://localhost:4318/v1/logs -H "Content-Type: application/json" -d "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{\"body\":{\"kvlistValue\":{\"values\":[{\"key\":\"eventSource\",\"value\":{\"stringValue\":\"s3.amazonaws.com\"}},{\"key\":\"eventName\",\"value\":{\"stringValue\":\"CreateBucket\"}},{\"key\":\"sourceIPAddress\",\"value\":{\"stringValue\":\"198.51.100.42\"}}]}}}]}]}]}"
   ```
2. Confirme a saída normalizada no arquivo local `data/ocsf_6003_normalized.jsonl`.
3. Acesse o Splunk Web (`http://localhost:8000`) $\rightarrow$ **Search & Reporting** e execute:
   ```spl
   index="otel_ocsf" sourcetype="ocsf:api_activity:6003"
   ```
   Você verá o evento já normalizado com os atributos `ocsf.class_uid=6003`, `ocsf.metadata.version=1.9.0`, `ocsf.api.service.name=s3.amazonaws.com` e `ocsf.api.operation=CreateBucket`.

---

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
