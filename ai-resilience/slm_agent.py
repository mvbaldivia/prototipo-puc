"""Cliente de Inferência para SLM Local (Gemma 3 1B GGUF 4-bit).

Opera exclusivamente sobre esqueletos estruturais sanitizados em rede
air-gapped, gerando propostas de declarações OTTL para OCSF v1.9.0 (6003).
"""

import json
import os
import urllib.request
from typing import Any, Dict, List

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
SLM_MODEL = os.getenv("SLM_MODEL", "gemma3:1b")

_SYSTEM_PROMPT = (
    "Você é um compilador de regras OTTL para o padrão OCSF v1.9.0 classe API Activity (6003). "
    "Receba APENAS um esqueleto JSON sanitizado delimitado por <SKELETON> e </SKELETON>. "
    "Retorne exclusivamente um objeto JSON com o campo 'ottl_statements' contendo declarações "
    "no formato: set(attributes[\"ocsf.<caminho>\"], body[\"<campo>\"])"
)


def build_delimited_prompt(skeleton: Dict[str, Any]) -> str:
    """Constrói prompt com delimitadores rígidos separando instruções de dados."""
    serialized = json.dumps(skeleton, ensure_ascii=False, indent=2)
    return (
        f"{_SYSTEM_PROMPT}\n\n"
        f"<SKELETON>\n{serialized}\n</SKELETON>\n\n"
        "Mapeie para os caminhos canônicos: ocsf.api.service.name, ocsf.api.operation, "
        "ocsf.src_endpoint.ip, ocsf.actor.user.uid e ocsf.resources.name."
    )


def propose_ottl_mapping(skeleton: Dict[str, Any], offline_dry_run: bool = False) -> List[str]:
    """Solicita ao SLM local uma lista de declarações OTTL candidatas."""
    prompt = build_delimited_prompt(skeleton)

    if offline_dry_run:
        return _heuristic_fallback(skeleton)

    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/generate",
        data=json.dumps({"model": SLM_MODEL, "prompt": prompt, "stream": False, "format": "json"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = json.loads(resp.read().decode("utf-8")).get("response", "{}")
    parsed = json.loads(raw)
    return list(parsed.get("ottl_statements", []))


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
