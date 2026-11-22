"""Extrator Estrutural Seguro (Camada 3).

Remove valores textuais livres, credenciais, tokens e PII antes de acionar
o SLM local, neutralizando vetores de Indirect Prompt Injection (OWASP LLM01:2025).
"""

import re
from typing import Any

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ARN_RE = re.compile(r"^arn:aws:[a-z0-9-]+:[^:]*:\d*:.+$")
_ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _classify_scalar(value: Any) -> str:
    """Substitui um valor escalar por seu marcador estrutural tipado."""
    if isinstance(value, bool):
        return "<BOOL>"
    if isinstance(value, int):
        return "<INT>"
    if isinstance(value, float):
        return "<FLOAT>"
    if isinstance(value, str):
        stripped = value.strip()
        if _IPV4_RE.match(stripped):
            return "<IPV4>"
        if _EMAIL_RE.match(stripped):
            return "<EMAIL>"
        if _ARN_RE.match(stripped):
            return "<ARN>"
        if _ISO_TS_RE.match(stripped):
            return "<TIMESTAMP>"
        return "<STRING>"
    return "<NULL>"


def extract_structural_skeleton(payload: Any) -> Any:
    """Extrai exclusivamente a árvore de chaves JSON e tipos sintéticos.

    Nenhum valor textual livre (como userAgent, mensagens de erro ou segredos)
    é preservado na saída.
    """
    if isinstance(payload, dict):
        return {str(k): extract_structural_skeleton(v) for k, v in payload.items()}
    if isinstance(payload, list):
        if not payload:
            return []
        # Preserva apenas a estrutura representativa do primeiro elemento
        return [extract_structural_skeleton(payload[0])]
    return _classify_scalar(payload)
