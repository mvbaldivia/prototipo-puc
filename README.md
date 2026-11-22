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

### Passo 5: Gerar dados de teste (Normal e Drift) e validar no Splunk
1. Na pasta `prototype/`, utilize o script `gerar_testes.ps1` para enviar eventos normais, de *schema drift* ou ambos:
   ```powershell
   .\gerar_testes.ps1                        # Envia normais (AWS/Azure/GCP) + drift
   .\gerar_testes.ps1 -Modo normal -Repeticoes 5
   .\gerar_testes.ps1 -Modo drift
   ```
   *(Ou via Python: `python simulator/generate_events.py --mode both --count 1`.)*
2. Confirme as saídas nos arquivos locais `data/ocsf_6003_normalized.jsonl` e `data/dlq_quarantine.jsonl`.
3. Acesse o Splunk Web (`http://localhost:8000`) $\rightarrow$ **Search & Reporting** e execute:
   - **Eventos válidos OCSF `v1.9.0` (`6003`):**
     ```spl
     index="otel_ocsf" sourcetype="ocsf:api_activity:6003"
     ```
   - **Eventos em Quarentena / Schema Drift (DLQ):**
     ```spl
     index="otel_ocsf" sourcetype="ocsf:quarantine:dlq"
     ```

---

## Deploy no GCP (`prototipo-puc`) — Logs Reais do Tenant

1. Autenticar no GCP com sua conta do tenant:
   ```powershell
   gcloud auth login
   gcloud auth application-default login
   gcloud config set project prototipo-puc
   ```
2. Provisionar toda a infraestrutura (APIs, Artifact Registry `tcc-repo`, Log Sink de Cloud Audit Logs $\rightarrow$ Pub/Sub, IAM de menor privilégio, VPC com *Private Google Access* e VM `e2-standard-4` Spot):
   ```powershell
   cd infra/terraform
   terraform init
   terraform plan
   terraform apply
   ```
3. *(Opcional para CD automático via GitHub Actions)* Configurar o *Workload Identity Pool* (`github-pool` / `github-provider`) no projeto `prototipo-puc` (`811890592302`) vinculado ao repositório `mvbaldivia/prototipo-puc`.
4. Ao concluir os ensaios do laboratório, destruir os recursos para evitar cobrança contínua:
   ```powershell
   terraform destroy
   ```
