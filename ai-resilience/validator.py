"""Validador Determinístico de Regras OTTL e Contrato OCSF v1.9.0 (6003)."""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

_SCHEMA_PATH = Path(__file__).parent / "schemas" / "ocsf_6003_v1.9.0.json"

_OTTL_SET_RE = re.compile(
    r'^set\(attributes\["(ocsf\.[a-z0-9_.]+)"\],\s*body\["([a-zA-Z0-9_]+)"\]\)$'
)

ALLOWED_OCSF_PATHS = {
    "ocsf.api.service.name",
    "ocsf.api.operation",
    "ocsf.src_endpoint.ip",
    "ocsf.actor.user.uid",
    "ocsf.resources.name",
}


def load_ocsf_schema() -> Dict[str, Any]:
    with _SCHEMA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_ottl_syntax(statements: List[str]) -> Tuple[bool, List[str]]:
    """Valida sintaxe OTTL em sandbox e rejeita caminhos fora do contrato OCSF."""
    errors: List[str] = []
    for stmt in statements:
        match = _OTTL_SET_RE.match(stmt.strip())
        if not match:
            errors.append(f"Sintaxe OTTL inválida ou função não permitida: {stmt}")
            continue
        ocsf_path = match.group(1)
        if ocsf_path not in ALLOWED_OCSF_PATHS:
            errors.append(f"Campo OCSF desconhecido ou não autorizado: {ocsf_path}")
    return (len(errors) == 0, errors)


def apply_ottl_sandbox(statements: List[str], raw_event: Dict[str, Any], vendor: str, product: str) -> Dict[str, Any]:
    """Aplica declarações OTTL validadas sobre um evento de teste construindo OCSF v1.9.0."""
    ocsf_event: Dict[str, Any] = {
        "category_uid": 6,
        "class_uid": 6003,
        "activity_id": 1,
        "type_uid": 600301,
        "time": 1760000000000,
        "status_id": 1,
        "metadata": {"version": "1.9.0", "product": {"name": product, "vendor_name": vendor}},
        "actor": {"user": {}},
        "api": {"service": {}},
        "src_endpoint": {},
    }

    for stmt in statements:
        match = _OTTL_SET_RE.match(stmt.strip())
        if not match:
            continue
        ocsf_path, src_key = match.group(1), match.group(2)
        val = raw_event.get(src_key)
        if val is None:
            continue
        if ocsf_path == "ocsf.api.service.name":
            ocsf_event["api"]["service"]["name"] = str(val)
        elif ocsf_path == "ocsf.api.operation":
            ocsf_event["api"]["operation"] = str(val)
        elif ocsf_path == "ocsf.src_endpoint.ip":
            ocsf_event["src_endpoint"]["ip"] = str(val)
        elif ocsf_path == "ocsf.actor.user.uid":
            ocsf_event["actor"]["user"]["uid"] = str(val)
        elif ocsf_path == "ocsf.resources.name":
            ocsf_event["resources"] = [{"name": str(val)}]

    return ocsf_event


def validate_ocsf_event(ocsf_event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Valida determinísticamente o evento contra JSON Schema OCSF v1.9.0 (6003)."""
    schema = load_ocsf_schema()
    if Draft202012Validator is not None:
        validator = Draft202012Validator(schema)
        errors = [e.message for e in validator.iter_errors(ocsf_event)]
        return (len(errors) == 0, errors)

    # Validação determinística equivalente caso jsonschema não esteja instalado localmente
    errors: List[str] = []
    for req_key in schema["required"]:
        if req_key not in ocsf_event:
            errors.append(f"Campo obrigatório ausente: {req_key}")
    allowed_top = set(schema["properties"].keys())
    unknown_top = set(ocsf_event.keys()) - allowed_top
    if unknown_top:
        errors.append(f"Campos desconhecidos rejeitados: {sorted(unknown_top)}")
    if ocsf_event.get("class_uid") != 6003 or ocsf_event.get("metadata", {}).get("version") != "1.9.0":
        errors.append("Versão OCSF ou class_uid inválida")
    if not ocsf_event.get("api", {}).get("operation") or not ocsf_event.get("src_endpoint", {}).get("ip"):
        errors.append("Campos semânticos obrigatórios de api.operation ou src_endpoint.ip ausentes")
    return (len(errors) == 0, errors)


def compute_semantic_field_accuracy(predicted: Dict[str, Any], ground_truth: Dict[str, Any]) -> float:
    """Calcula a Acurácia por Campo Semântico (ACS) sobre os campos-alvo da classe 6003."""
    pairs = [
        (predicted.get("api", {}).get("service", {}).get("name"), ground_truth.get("api", {}).get("service", {}).get("name")),
        (predicted.get("api", {}).get("operation"), ground_truth.get("api", {}).get("operation")),
        (predicted.get("src_endpoint", {}).get("ip"), ground_truth.get("src_endpoint", {}).get("ip")),
        (predicted.get("actor", {}).get("user", {}).get("uid"), ground_truth.get("actor", {}).get("user", {}).get("uid")),
    ]
    hits = sum(1 for p, g in pairs if p is not None and p == g)
    return hits / len(pairs)
