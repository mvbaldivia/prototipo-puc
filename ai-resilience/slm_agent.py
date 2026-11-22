"""Cliente de Inferência para SLM Local (Gemma 3 1B GGUF 4-bit).

Opera exclusivamente sobre esqueletos estruturais sanitizados em rede
air-gapped, gerando mapeamentos semânticos compilados deterministicamente para OTTL (OCSF v1.9.0 / 6003).
"""

import json
import os
import urllib.request
from typing import Any, Dict, List

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
SLM_MODEL = os.getenv("SLM_MODEL", "gemma3:1b")

_SYSTEM_PROMPT = (
    "You are a cybersecurity schema mapper for OCSF v1.9.0 API Activity (6003). "
    "Given ONLY the JSON keys inside <SKELETON>...</SKELETON>, return a JSON object mapping "
    "each OCSF target path to the exact matching key name from the skeleton (or null if absent)."
)


def build_delimited_prompt(skeleton: Dict[str, Any]) -> str:
    """Constrói prompt com delimitadores rígidos separando instruções de dados."""
    serialized = json.dumps(skeleton, ensure_ascii=False, indent=2)
    return (
        f"{_SYSTEM_PROMPT}\n\n"
        "Example input:\n"
        '{"svcHost": "<STRING>", "verb": "<STRING>", "originIp": "<IPV4>", "userArn": "<ARN>", "bucket": "<STRING>"}\n'
        "Example output JSON:\n"
        '{"ocsf.api.service.name": "svcHost", "ocsf.api.operation": "verb", '
        '"ocsf.src_endpoint.ip": "originIp", "ocsf.actor.user.uid": "userArn", "ocsf.resources.name": "bucket"}\n\n'
        f"<SKELETON>\n{serialized}\n</SKELETON>\n\n"
        "Return ONLY the JSON object with keys: ocsf.api.service.name, ocsf.api.operation, "
        "ocsf.src_endpoint.ip, ocsf.actor.user.uid, ocsf.resources.name."
    )


def _compile_mapping_to_ottl(parsed: Dict[str, Any], skeleton: Dict[str, Any]) -> List[str]:
    """Compila o JSON de mapeamento do SLM para declarações OTTL determinísticas."""
    if "ottl_statements" in parsed and isinstance(parsed["ottl_statements"], list):
        return list(parsed["ottl_statements"])

    statements: List[str] = []
    valid_keys = set(skeleton.keys())
    for ocsf_path, src_key in parsed.items():
        if isinstance(ocsf_path, str) and ocsf_path.startswith("ocsf.") and isinstance(src_key, str):
            clean_key = src_key.strip()
            if clean_key in valid_keys:
                statements.append(f'set(attributes["{ocsf_path}"], body["{clean_key}"])')
    return statements


def propose_ottl_mapping(skeleton: Dict[str, Any], offline_dry_run: bool = False) -> List[str]:
    """Solicita ao SLM local o mapeamento semântico e compila para OTTL."""
    prompt = build_delimited_prompt(skeleton)

    if offline_dry_run:
        return _heuristic_fallback(skeleton)

    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/generate",
        data=json.dumps({
            "model": SLM_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0},
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = json.loads(resp.read().decode("utf-8")).get("response", "{}")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        return []
    return _compile_mapping_to_ottl(parsed, skeleton)


def _heuristic_fallback(skeleton: Dict[str, Any]) -> List[str]:
    """Modo determinístico de apoio para testes unitários sem daemon Ollama ativo."""
    statements: List[str] = []
    if "newServiceEndpoint" in skeleton:
        statements.append('set(attributes["ocsf.api.service.name"], body["newServiceEndpoint"])')
    if "apiActionName" in skeleton:
        statements.append('set(attributes["ocsf.api.operation"], body["apiActionName"])')
    if "clientIp" in skeleton:
        statements.append('set(attributes["ocsf.src_endpoint.ip"], body["clientIp"])')
    if "actorPrincipal" in skeleton:
        statements.append('set(attributes["ocsf.actor.user.uid"], body["actorPrincipal"])')
    return statements
