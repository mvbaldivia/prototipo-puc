"""Suíte de validação determinística, regressão e segurança (OWASP LLM01:2025)."""

import json
from sanitizer import extract_structural_skeleton
from slm_agent import build_delimited_prompt, propose_ottl_mapping
from validator import (
    apply_ottl_sandbox,
    compute_semantic_field_accuracy,
    validate_ocsf_event,
    validate_ottl_syntax,
)
from generate_events import sample_schema_drift_with_injection


def test_sanitizer_blocks_prompt_injection_and_pii():
    malicious_event = sample_schema_drift_with_injection()
    skeleton = extract_structural_skeleton(malicious_event)
    serialized = json.dumps(skeleton)

    # Nenhum valor livre, instrução maliciosa, PII ou segredo pode chegar ao prompt do SLM
    assert "Ignore all previous instructions" not in serialized
    assert "alice.silva@empresa.com.br" not in serialized
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "198.51.100.99" not in serialized

    assert skeleton["clientIp"] == "<IPV4>"
    assert skeleton["actorPrincipal"] == "<EMAIL>"
    assert skeleton["userAgent"] == "<STRING>"


def test_delimited_prompt_contains_only_skeleton():
    skeleton = extract_structural_skeleton(sample_schema_drift_with_injection())
    prompt = build_delimited_prompt(skeleton)
    assert "<SKELETON>" in prompt and "</SKELETON>" in prompt
    assert "Ignore all previous instructions" not in prompt


def test_rejects_unknown_ocsf_field_and_unsafe_syntax():
    bad_statements = [
        'set(attributes["ocsf.invented_field"], body["clientIp"])',
        'exec("rm -rf /")',
    ]
    ok, errors = validate_ottl_syntax(bad_statements)
    assert not ok
    assert len(errors) == 2


def test_end_to_end_resilience_ocsf_1_9_0_and_acs_threshold():
    raw_event = sample_schema_drift_with_injection()
    skeleton = extract_structural_skeleton(raw_event)
    statements = propose_ottl_mapping(skeleton, offline_dry_run=True)

    syntax_ok, syntax_errors = validate_ottl_syntax(statements)
    assert syntax_ok, f"Erros de sintaxe OTTL: {syntax_errors}"

    ocsf_event = apply_ottl_sandbox(statements, raw_event, vendor="AWS", product="CloudTrail")
    schema_ok, schema_errors = validate_ocsf_event(ocsf_event)
    assert schema_ok, f"Falha na validação JSON Schema OCSF v1.9.0: {schema_errors}"

    ground_truth = {
        "api": {"service": {"name": "iam.amazonaws.com"}, "operation": "CreateAccessKey"},
        "src_endpoint": {"ip": "198.51.100.99"},
        "actor": {"user": {"uid": "alice.silva@empresa.com.br"}},
    }
    acs = compute_semantic_field_accuracy(ocsf_event, ground_truth)
    assert acs >= 0.85, f"ACS abaixo da meta (0.85): {acs}"
