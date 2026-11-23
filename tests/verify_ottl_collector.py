"""Validação ponta a ponta do bloco OTTL no container otel/opentelemetry-collector-contrib:0.114.0."""

import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

PROTO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROTO_ROOT / "ai-resilience"))
sys.path.insert(0, str(PROTO_ROOT / "simulator"))

from generate_events import _to_otlp_value
from validator import validate_ocsf_event


def _from_otlp_value(val: Dict[str, Any]) -> Any:
    if "stringValue" in val:
        return val["stringValue"]
    if "intValue" in val:
        return int(val["intValue"])
    if "doubleValue" in val:
        return float(val["doubleValue"])
    if "boolValue" in val:
        return bool(val["boolValue"])
    if "arrayValue" in val:
        return [_from_otlp_value(v) for v in val["arrayValue"].get("values", [])]
    if "kvlistValue" in val:
        return {kv["key"]: _from_otlp_value(kv["value"]) for kv in val["kvlistValue"].get("values", [])}
    return None


def _extract_transform_yaml() -> str:
    """Extrai o bloco transform/ocsf_6003 real de otel-collector-config.yaml sem depender de PyYAML."""
    lines = (PROTO_ROOT / "otel-collector" / "otel-collector-config.yaml").read_text(encoding="utf-8").splitlines()
    captured: List[str] = []
    inside = False
    for line in lines:
        if line.startswith("  transform/ocsf_6003:"):
            inside = True
        elif inside and line.strip() and not line.startswith("    "):
            break
        if inside:
            captured.append(line)
    return "\n".join(captured)


def main() -> None:
    transform_block = _extract_transform_yaml()
    test_cfg_yaml = (
        "receivers:\n"
        "  otlp:\n"
        "    protocols:\n"
        "      http:\n"
        "        endpoint: 0.0.0.0:4318\n\n"
        "processors:\n"
        f"{transform_block}\n\n"
        "exporters:\n"
        "  file:\n"
        "    path: /out/ottl_out.json\n\n"
        "service:\n"
        "  pipelines:\n"
        "    logs:\n"
        "      receivers: [otlp]\n"
        "      processors: [transform/ocsf_6003]\n"
        "      exporters: [file]\n"
    )

    cloudtrail_input = {
        "eventVersion": "1.08",
        "eventTime": "2026-10-12T14:20:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "CreateBucket",
        "sourceIPAddress": "198.51.100.42",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/sec-admin"},
        "requestParameters": {"bucketName": "corp-audit-logs-prod"},
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        cfg_file = tmp / "collector-test.yaml"
        out_dir = tmp / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        cfg_file.write_text(test_cfg_yaml, encoding="utf-8")

        cname = "otel-ottl-verify-test"
        subprocess.run(["docker", "rm", "-f", cname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                cname,
                "-p",
                "14318:4318",
                "-v",
                f"{cfg_file}:/etc/otelcol-contrib/config.yaml:ro",
                "-v",
                f"{out_dir}:/out",
                "otel/opentelemetry-collector-contrib:0.114.0",
                "--config=/etc/otelcol-contrib/config.yaml",
            ],
            check=True,
        )

        try:
            payload = json.dumps({
                "resourceLogs": [{
                    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "ottl-verify"}}]},
                    "scopeLogs": [{"logRecords": [{"timeUnixNano": "1791814800000000000", "body": _to_otlp_value(cloudtrail_input)}]}],
                }]
            }).encode("utf-8")

            # Aguarda o Collector subir na porta 14318 e envia o evento
            for _ in range(20):
                try:
                    req = urllib.request.Request(
                        "http://127.0.0.1:14318/v1/logs",
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if resp.status == 200:
                            break
                except Exception:
                    time.sleep(0.5)
            else:
                raise RuntimeError("OTel Collector não respondeu em 127.0.0.1:14318/v1/logs")

            out_file = out_dir / "ottl_out.json"
            for _ in range(20):
                if out_file.exists() and out_file.stat().st_size > 0:
                    break
                time.sleep(0.3)
            else:
                logs = subprocess.run(["docker", "logs", cname], capture_output=True, text=True).stdout
                raise RuntimeError(f"Arquivo de saída não gerado. Logs:\n{logs}")

            raw_export = json.loads(out_file.read_text(encoding="utf-8").splitlines()[0])
            log_rec = raw_export["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
            ocsf_output = _from_otlp_value(log_rec["body"])
        finally:
            subprocess.run(["docker", "rm", "-f", cname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Valida contra JSON Schema OCSF v1.9.0 (6003)
    # Nota: se o Collector adicionar campos extras não previstos no schema estrito (ex.: category_name), registra ambos
    schema_ok, schema_errors = validate_ocsf_event(ocsf_output)
    evidence = {
        "collector_image": "otel/opentelemetry-collector-contrib:0.114.0",
        "input_cloudtrail": cloudtrail_input,
        "collector_ocsf_output": ocsf_output,
        "strict_schema_valid": schema_ok,
        "strict_schema_notes": schema_errors,
    }
    ev_path = PROTO_ROOT / "data" / "ottl_execution_evidence.json"
    ev_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(evidence, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
