"""Envia os resultados do benchmark (benchmark_results.json) para o Splunk HEC."""

import json
import os
import ssl
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = Path(os.getenv("BENCHMARK_JSON", str(ROOT / "data" / "benchmark_results.json")))
HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://splunk:8088/services/collector/event")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "fb20f901-4394-4248-9a3d-00d919c0e49e")


def main() -> None:
    d = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    events = [{"metric_group": "conformance", **d["conformance_and_bytes"]}]
    for t in d["throughput"]:
        events.append({"metric_group": "throughput", "events_label": f"{t['events'] // 1000}k eventos", **t})
    ai = d["ai_schema_drift"]
    for label, val in [
        ("1. ACS Global", ai["avg_acs_pct"]),
        ("2. ACS AWS", ai["aws_acs_pct"]),
        ("3. ACS Azure", ai["azure_acs_pct"]),
        ("4. ACS GCP", ai["gcp_acs_pct"]),
        ("5. Sintaxe OTTL", ai["syntax_approval_pct"]),
        ("6. Schema OCSF", ai["schema_valid_pct"]),
    ]:
        events.append({"metric_group": "ai_accuracy", "dimension": label, "score_pct": val})

    payload = "\n".join(
        json.dumps({"index": "otel_ocsf", "sourcetype": "ocsf:benchmark:metrics", "source": "benchmark-gcp", "event": e})
        for e in events
    ).encode("utf-8")

    req = urllib.request.Request(
        HEC_URL,
        data=payload,
        headers={"Authorization": f"Splunk {HEC_TOKEN}", "Content-Type": "application/json"},
        method="POST",
    )
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        print(resp.read().decode("utf-8"))


if __name__ == "__main__":
    main()
