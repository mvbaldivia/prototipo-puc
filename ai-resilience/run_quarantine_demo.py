"""Demonstração do fluxo Validador & Quarentena (DLQ -> Camada 3 -> Governança HITL)."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ai-resilience"))
sys.path.insert(0, str(ROOT / "simulator"))

from generate_events import sample_schema_drift_with_injection
from sanitizer import extract_structural_skeleton
from slm_agent import propose_ottl_mapping
from validator import (
    apply_ottl_sandbox,
    compute_semantic_field_accuracy,
    validate_ocsf_event,
    validate_ottl_syntax,
)


def main() -> None:
    data_dir = ROOT / "data"
    dlq_path = data_dir / "dlq_quarantine.jsonl"

    if not dlq_path.exists() or not dlq_path.read_text(encoding="utf-8").strip():
        print("[ERRO] Nenhum evento encontrado em data/dlq_quarantine.jsonl")
        sys.exit(1)

    dlq_lines = [l for l in dlq_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"[1. DLQ] {len(dlq_lines)} lote(s) capturado(s) na fila de quarentena: {dlq_path.name}")

    # Evento fora de padrão capturado pela Camada 2 (representado com campos originais para simulação na Camada 3)
    raw_drift_event = sample_schema_drift_with_injection()

    # Etapa 2: Extrator Estrutural Seguro (mitigação de Prompt Injection e PII)
    skeleton = extract_structural_skeleton(raw_drift_event)
    print("[2. SANITIZADOR] Esqueleto estrutural extraído (sem valores livres / PII / injection):")
    print(json.dumps(skeleton, indent=2, ensure_ascii=False))

    # Etapa 3A: Simulação de regra inválida / campo desconhecido -> Quarentena/Rejeição
    bad_rule = ['set(attributes["ocsf.invented_field"], body["clientIp"])']
    ok_bad, bad_errors = validate_ottl_syntax(bad_rule)
    rejected_path = data_dir / "dlq_rejected.jsonl"
    rejected_path.write_text(
        json.dumps({"rejected_rule": bad_rule, "errors": bad_errors}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[3A. VALIDADOR - REJEIÇÃO] Sintaxe/campo desconhecido bloqueado (ok={ok_bad}): {bad_errors}")

    # Etapa 3B: Proposta válida -> Validação Determinística OCSF v1.9.0 (6003) -> Candidato a PR (HITL)
    candidate_rules = propose_ottl_mapping(skeleton, offline_dry_run=True)
    syntax_ok, syntax_errors = validate_ottl_syntax(candidate_rules)
    ocsf_event = apply_ottl_sandbox(candidate_rules, raw_drift_event, vendor="AWS", product="CloudTrail")
    schema_ok, schema_errors = validate_ocsf_event(ocsf_event)

    ground_truth = {
        "api": {"service": {"name": "iam.amazonaws.com"}, "operation": "CreateAccessKey"},
        "src_endpoint": {"ip": "198.51.100.99"},
        "actor": {"user": {"uid": "alice.silva@empresa.com.br"}},
    }
    acs = compute_semantic_field_accuracy(ocsf_event, ground_truth)

    assert syntax_ok and schema_ok and acs >= 0.85, f"Falha: {syntax_errors} / {schema_errors}"

    pr_path = data_dir / "candidate_pr_rule.ottl"
    pr_path.write_text("\n".join(candidate_rules) + "\n", encoding="utf-8")
    print(f"[3B. VALIDADOR - APROVADO PARA PR] OCSF v1.9.0 válido={schema_ok} | ACS={acs:.0%}")
    print(f"[4. GOVERNANÇA HITL] Regra candidata salva para revisão humana em: {pr_path.name}")


if __name__ == "__main__":
    main()
