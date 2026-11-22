param(
    [ValidateSet("normal", "drift", "ambos")]
    [string]$Modo = "ambos",
    [int]$Repeticoes = 1
)

$modoPy = switch ($Modo) {
    "normal" { "normal" }
    "drift"  { "drift" }
    "ambos"  { "both" }
}

Write-Host "Enviando eventos de teste (modo=$Modo, repeticoes=$Repeticoes)..." -ForegroundColor Cyan
python "$PSScriptRoot\simulator\generate_events.py" --mode $modoPy --count $Repeticoes

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nConsultas no Splunk Web (http://localhost:8000):" -ForegroundColor Green
    Write-Host '  Normais (OCSF v1.9.0): index="otel_ocsf" sourcetype="ocsf:api_activity:6003"'
    Write-Host '  Quarentena (DLQ):      index="otel_ocsf" sourcetype="ocsf:quarantine:dlq"'
}
