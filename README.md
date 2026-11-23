# Protótipo TCC PUCPR Digital — Pipeline Autônomo Multi-Cloud (OTel + OCSF v1.9.0 + SLM)

Implementação prática do artigo **"Pipeline Autônomo de Normalização Semântica de Telemetria Multi-Cloud Baseado em OpenTelemetry, OCSF e Small Language Models para Engenharia de Detecção"**.

- **Projeto GCP:** `prototipo-puc` (`811890592302`)
- **Esquema Canônico:** OCSF `v1.9.0` — Classe `API Activity (6003)`
- **SLM Local:** `Gemma 3 1B` (GGUF 4-bit, `806 MB`, execução *air-gapped* em CPU)
- **SIEM (Local e Cloud):** Splunk Enterprise via HTTP Event Collector (HEC) na porta `8088`, índice `otel_ocsf`

---

## 1. Estrutura do Protótipo

```text
prototype/
├── ai-resilience/                # Camada 3: Sanitizador, cliente SLM e validador OCSF
│   ├── schemas/                  # Contrato JSON Schema OCSF v1.9.0 (6003)
│   ├── sanitizer.py              # Extrator estrutural (mitiga Prompt Injection e PII)
│   ├── slm_agent.py              # Cliente Ollama/Gemma 3 1B + compilador JSON -> OTTL
│   ├── validator.py              # Validador sintático OTTL, JSON Schema e cálculo de ACS
│   └── run_quarantine_demo.py    # Demonstração do fluxo DLQ -> Camada 3 -> PR candidato
├── benchmark/                    # Validação experimental completa (Tabela 3 e 4 do TCC)
│   ├── dataset_builder.py        # 1.500 eventos base + 20 drift + 30 payloads maliciosos
│   └── run_benchmark.py          # Executor de conformidade, EPS/latência, ACS e segurança
├── otel-collector/               # Camada 2: OpenTelemetry Collector Contrib v0.114.0
│   ├── otel-collector-config.yaml      # Configuração local (OTLP -> Splunk local)
│   └── otel-collector-gcp-config.yaml  # Configuração GCP (Pub/Sub + OTLP -> Splunk Cloud)
├── simulator/                    # Camada 1: Gerador multi-cloud (AWS/Azure/GCP) + drift
│   └── generate_events.py
├── splunk/                       # Configuração e Dashboard do Splunk
│   ├── docker-compose.splunk.yml # Splunk local opcional (8000, 8088, 9997)
│   ├── indexes.conf              # Definição do índice otel_ocsf
│   ├── dashboard_tcc_ocsf.xml    # Dashboard SimpleXML (KPIs, pizza, colunas, EPS)
│   └── push_benchmark_to_splunk.py
├── tests/                        # Suíte pytest (sanitização, OCSF v1.9.0 e regressão)
├── infra/terraform/              # IaC GCP (VPC, NAT, IAP, Pub/Sub, Log Sink, WIF, VM)
├── .github/workflows/ci-cd.yml   # Esteira CI/CD com Workload Identity Federation
├── cloudbuild.yaml               # Build automatizado da imagem ai-resilience
├── docker-compose.yml            # Stack local (OTel + Ollama air-gapped + AI Resilience)
├── docker-compose.gcp.yml        # Stack GCP (Splunk + OTel + Ollama air-gapped + AI)
├── gerar_testes.ps1              # Atalho PowerShell para gerar eventos normais e drift
└── .env.example                  # Modelo de variáveis locais (sem segredos)
```

---

## 2. Execução Local (Custo Zero)

### Passo 1: Configurar variáveis locais (`.env`)
```powershell
Copy-Item .env.example .env
```
Edite o `.env` com seu token HEC local (o arquivo `.env` é ignorado pelo `.gitignore` e nunca vai para o GitHub):
```ini
SPLUNK_HEC_ENDPOINT=https://host.docker.internal:8088/services/collector
SPLUNK_HEC_TOKEN=seu-token-hec-aqui
```

### Passo 2: Subir ou configurar o Splunk Local (porta `8088` aberta)
- Se já tiver um Splunk rodando, garanta a porta `"8088:8088"`, o índice `otel_ocsf` e o HEC habilitado (*Global Settings $\rightarrow$ All Tokens = Enabled*).
- Ou suba com a configuração incluída:
  ```powershell
  docker compose --env-file .env -f splunk/docker-compose.splunk.yml up -d
  ```

### Passo 3: Executar testes unitários e de segurança (`pytest`)
```powershell
pip install -r requirements.txt
python -m pytest -v
```

### Passo 4: Subir o Pipeline Local e gerar eventos de teste
```powershell
docker compose up -d --build
.\gerar_testes.ps1                              # Envia normais (AWS/Azure/GCP) + drift
.\gerar_testes.ps1 -Modo normal -Repeticoes 5   # Apenas eventos nominais
.\gerar_testes.ps1 -Modo drift                  # Apenas eventos para quarentena
```
Consulte no Splunk Web (`http://localhost:8000`):
- **Normais (`OCSF v1.9.0`):** `index="otel_ocsf" sourcetype="ocsf:api_activity:6003"`
- **Quarentena (DLQ):** `index="otel_ocsf" sourcetype="ocsf:quarantine:dlq"`

### Passo 5: Reprodução rápida das evidências pela banca
- **Testes unitários e de segurança (OWASP LLM01 / OCSF v1.9.0):** `python -m pytest tests/test_pipeline.py -v`
- **Validação real do OTTL no OTel Collector Contrib v0.114.0 (requer Docker):** `python tests/verify_ottl_collector.py`
- **Simulação offline do benchmark completo:** `python benchmark/run_benchmark.py --skip-otlp --dry-run-slm`
- **Evidências consolidadas versionadas:** `data/benchmark_results.json`, `data/adversarial_trace_samples.json` e `data/ottl_execution_evidence.json`.

---

## 3. Passo a Passo Completo — Deploy no GCP (`prototipo-puc`)

### Passo 1: Autenticação e alinhamento de cota no `gcloud`
No PowerShell:
```powershell
gcloud auth login
gcloud auth application-default login
gcloud config set project prototipo-puc
gcloud auth application-default set-quota-project prototipo-puc
```

### Passo 2: Provisionar a Infraestrutura com Terraform (`infra/terraform/`)
O Terraform cria automaticamente:
- APIs habilitadas (`compute`, `pubsub`, `logging`, `artifactregistry`, `cloudbuild`, `iam`, `iamcredentials`);
- Repositório Docker `tcc-repo` no Artifact Registry (`us-central1`);
- VPC `otel-ocsf-vpc`, sub-rede `10.20.0.0/24` com *Private Google Access*, Cloud Router/NAT e firewall IAP (`35.235.240.0/20` $\rightarrow$ TCP `22`);
- Tópicos/assinatura Pub/Sub (`telemetry-ingest`, `telemetry-dlq`, `telemetry-ingest-sub`) e **Log Sink** (`gcp-audit-to-otel-pubsub`) capturando os *Cloud Audit Logs* reais do tenant;
- Contas separadas por menor privilégio: `otel-ocsf-collector-sa` (runtime) e `github-deploy-sa` (CI/CD via *Workload Identity Federation* `github-pool`);
- VM `otel-ocsf-slm-node` (`e2-standard-4` Spot, 4 vCPUs, 16 GB RAM, disco 50 GB, sem IP público).

```powershell
cd infra/terraform
terraform init
terraform plan
terraform apply
```

### Passo 3: Esteira CI/CD no GitHub Actions
Após o `terraform apply` (que provisiona o `github-pool` e a `github-deploy-sa`), cada `push` ou *merge* aprovado na branch `main` dispara automaticamente:
1. **Job CI:** Executa `pytest -v` (sanitização, OCSF `v1.9.0` e regressão) e `terraform validate`;
2. **Job CD:** Autentica sem chave JSON via *Workload Identity Federation* e executa `gcloud builds submit` (`cloudbuild.yaml`) publicando a imagem `ai-resilience` em `tcc-repo`.

### Passo 4: Copiar arquivos e subir a stack na VM (`docker-compose.gcp.yml`)
1. Transfira os arquivos e o `.env` para a VM via túnel IAP:
   ```powershell
   gcloud compute scp --recurse --zone=us-central1-a --project=prototipo-puc --tunnel-through-iap docker-compose.gcp.yml otel-collector ai-resilience splunk benchmark simulator requirements.txt .env otel-ocsf-slm-node:/tmp/
   ```
2. Dentro da VM (`gcloud compute ssh otel-ocsf-slm-node --zone=us-central1-a --project=prototipo-puc --tunnel-through-iap`):
   ```bash
   sudo mkdir -p /opt/otel/prototipo-puc/data
   sudo chmod 777 /opt/otel/prototipo-puc/data
   sudo mv /tmp/docker-compose.gcp.yml /tmp/otel-collector /tmp/ai-resilience /tmp/splunk /tmp/benchmark /tmp/simulator /tmp/requirements.txt /tmp/.env /opt/otel/prototipo-puc/
   cd /opt/otel/prototipo-puc
   sudo docker compose --env-file .env -f docker-compose.gcp.yml up -d --build
   ```
3. *(Primeira execução)* Baixar o modelo `gemma3:1b` (~806 MB) no `ollama` mantendo o isolamento *air-gapped* após o download:
   ```bash
   sudo docker network connect prototipo-puc_telemetry_net prototipo-puc-ollama-1
   sudo docker exec prototipo-puc-ollama-1 ollama pull gemma3:1b
   sudo docker network disconnect prototipo-puc_telemetry_net prototipo-puc-ollama-1
   ```
4. *(Primeira execução)* Criar o índice `otel_ocsf`, habilitar HEC na porta `8088` e vincular o token no `splunk-gcp`:
   ```bash
   sudo docker exec -u splunk splunk-gcp /opt/splunk/bin/splunk add index otel_ocsf -auth admin:Changeme123!
   sudo docker exec -u splunk splunk-gcp /opt/splunk/bin/splunk http-event-collector enable -uri https://127.0.0.1:8089 -enable-ssl 1 -port 8088 -auth admin:Changeme123!
   sudo docker exec -u splunk splunk-gcp /opt/splunk/bin/splunk http-event-collector update splunk_hec_token -index otel_ocsf -indexes otel_ocsf -disabled 0 -uri https://127.0.0.1:8089 -auth admin:Changeme123!
   sudo docker compose -f docker-compose.gcp.yml restart otel-collector
   ```

### Passo 5: Acessar o Splunk da Cloud via Proxy Seguro (Túnel IAP)
No PowerShell local (mantenha a janela aberta enquanto usar o navegador):
```powershell
gcloud compute ssh otel-ocsf-slm-node --zone=us-central1-a --project=prototipo-puc --tunnel-through-iap '--' -N -L 8001:localhost:8000
```
Acesse no navegador:
- **Splunk Web:** `http://localhost:8001` (`admin` / `Changeme123!`)
- **Dashboard TCC:** `http://localhost:8001/en-US/app/search/tcc_ocsf_dashboard`
- **Buscas SPL:**
  - Eventos reais e simulados normalizados: `index="otel_ocsf" sourcetype="ocsf:api_activity:6003"`
  - Eventos em quarentena: `index="otel_ocsf" sourcetype="ocsf:quarantine:dlq"`

### Passo 6: Executar o Benchmark Experimental na VM
Dentro da VM (ou via `gcloud compute ssh ... --command`), copie `benchmark/` e `simulator/` para o container `ai-resilience` e execute:
```bash
sudo docker cp /opt/otel/prototipo-puc/benchmark prototipo-puc-ai-resilience-1:/app/
sudo docker cp /opt/otel/prototipo-puc/simulator prototipo-puc-ai-resilience-1:/app/
sudo docker exec prototipo-puc-ai-resilience-1 python /app/benchmark/run_benchmark.py --endpoint http://otel-collector:4318/v1/logs
```

### Passo 7: Encerramento e Controle de Custos
Ao concluir os ensaios no GCP, destrua os recursos para zerar qualquer cobrança:
```powershell
cd infra/terraform
terraform destroy
```
