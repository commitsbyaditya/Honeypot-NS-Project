$ErrorActionPreference = "SilentlyContinue"

$apiBases = @(
  "http://localhost:8081",
  "http://localhost:8080",
  "http://localhost:5173"
)

foreach ($base in $apiBases) {
  try {
    Invoke-RestMethod -Method Post -Uri ($base + "/api/simulation/stop-all") -ContentType "application/json" -Body "{}" | Out-Null
  } catch {
    # Ignore and continue. Force-kill fallback below is authoritative.
  }
}

$pattern = "run_all_simulators\.py|attack_simulator(_arp|_dns|_icmp|_portscan)?\.py"
$simProcs = Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match $pattern }

if (-not $simProcs) {
  Write-Output "No running simulator processes found."
  exit 0
}

$killed = 0
foreach ($proc in $simProcs) {
  try {
    Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
    $killed += 1
  } catch {
    Write-Output ("Failed to stop simulator PID {0}" -f $proc.ProcessId)
  }
}

Write-Output ("Kill switch done. Stopped {0} simulator process(es)." -f $killed)