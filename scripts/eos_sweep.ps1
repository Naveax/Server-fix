param(
  [int]$Repeats = 20,
  [int]$Clients = 8,
  [int]$DurationSecs = 20,
  [int]$WarmupSecs = 3,
  [int]$TelemetryPerTick = 80,
  [int]$ServerMaxPacketsPerTick = 50,
  [int]$JitterMs = 30,
  [double]$DropRate = 0.03,

  [int]$ProxyWorkers = 1,
  [int[]]$ProxyBatchSizes = @(32, 64),

  # Upstream (client->server) per-session queues.
  [int]$ProxyQueueCapacity = 128,
  [int]$ProxyTelemetryQueueCapacity = 32,
  [int]$ProxyCriticalQueueCapacity = 96,
  [ValidateSet("drop-newest", "drop-oldest", "block-with-timeout")]
  [string]$ProxyCriticalOverflow = "drop-oldest",
  [int]$ProxyCriticalBlockTimeoutMs = 5,

  # Downstream (server->client) shared queues.
  # If you omit these, nx_proxy will fall back to the upstream capacities above.
  [int[]]$DownstreamTelemetryCaps = @(64, 128, 256),
  [int[]]$DownstreamCriticalCaps = @(128, 256, 512),

  # Load-shedding: drop stale packets from downstream queue (0 disables).
  [int[]]$DownstreamTelemetryTtlMs = @(100),
  [int[]]$DownstreamCriticalTtlMs = @(250),

  [string]$OutDir = ".",
  [string]$OutCsv = "nx_eos_sim_sweep.csv"
)

$ErrorActionPreference = "Stop"

function Resolve-OutDir {
  param([string]$Path)
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }
  return (Join-Path $repoRoot $Path)
}

if ($WarmupSecs -ge $DurationSecs) {
  throw "--WarmupSecs must be smaller than --DurationSecs"
}

# Ensure we run from repo root even if invoked from elsewhere.
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$outDirPath = Resolve-OutDir $OutDir
New-Item -ItemType Directory -Force -Path $outDirPath | Out-Null

Push-Location $repoRoot
try {
  Write-Host "Building nx_eos_sim (release) ..."
  cargo build --release -p nx_proxy --bin nx_eos_sim | Out-Host

  $exe = Join-Path $repoRoot "target\\release\\nx_eos_sim.exe"
  if (-not (Test-Path $exe)) {
    throw "missing binary: $exe"
  }

function Invoke-Sim {
  param(
    [int]$BatchSize,
    [int]$DownTele,
    [int]$DownCrit,
    [int]$TtlTele,
    [int]$TtlCrit
  )

  $name = "nx_eos_sim_sweep_b${BatchSize}_dq${DownTele}_${DownCrit}_ttl${TtlTele}_${TtlCrit}.json"
  $outPath = Join-Path $outDirPath $name

  $args = @(
    "--scenario=compare",
    "--compare-order=alternate",
    "--warmup-secs=$WarmupSecs",
    "--repeats=$Repeats",
    "--clients=$Clients",
    "--duration-secs=$DurationSecs",
    "--telemetry-per-tick=$TelemetryPerTick",
    "--server-max-packets-per-tick=$ServerMaxPacketsPerTick",
    "--jitter-ms=$JitterMs",
    "--drop-rate=$DropRate",

    "--proxy-workers=$ProxyWorkers",
    "--proxy-batch-size=$BatchSize",

    "--proxy-queue-capacity=$ProxyQueueCapacity",
    "--proxy-telemetry-queue-capacity=$ProxyTelemetryQueueCapacity",
    "--proxy-critical-queue-capacity=$ProxyCriticalQueueCapacity",
    "--proxy-critical-overflow=$ProxyCriticalOverflow",
    "--proxy-critical-block-timeout-ms=$ProxyCriticalBlockTimeoutMs",

    "--proxy-downstream-telemetry-queue-capacity=$DownTele",
    "--proxy-downstream-critical-queue-capacity=$DownCrit",
    "--proxy-downstream-telemetry-ttl-ms=$TtlTele",
    "--proxy-downstream-critical-ttl-ms=$TtlCrit",

    "--output=json",
    "--output-path=$outPath"
  )

  Write-Host "Running: batch=$BatchSize downQ=($DownTele,$DownCrit) ttl=($TtlTele,$TtlCrit)"
  & $exe @args | Out-Host

  $j = Get-Content $outPath -Raw | ConvertFrom-Json

  $negP99 = @($j.runs | Where-Object { $_.delta.control_lag_p99 -lt 0 }).Count
  $negP99Lt100 = @($j.runs | Where-Object { $_.delta.control_lag_p99 -lt -100 }).Count

  [pscustomobject]@{
    file            = $name
    batch_size      = $BatchSize
    down_tele       = $DownTele
    down_crit       = $DownCrit
    ttl_tele_ms     = $TtlTele
    ttl_crit_ms     = $TtlCrit

    avg_mean        = [double]$j.summary.delta_control_lag_avg.mean
    p99_mean        = [double]$j.summary.delta_control_lag_p99.mean
    p99_min         = [double]$j.summary.delta_control_lag_p99.min
    p99_pos         = "$($j.summary.delta_control_lag_p99.positive_runs)/$($j.summary.delta_control_lag_p99.total_runs)"
    neg_p99         = $negP99
    neg_p99_lt_100  = $negP99Lt100
  }
}

$rows = @()
foreach ($batch in $ProxyBatchSizes) {
  foreach ($dqT in $DownstreamTelemetryCaps) {
    foreach ($dqC in $DownstreamCriticalCaps) {
      foreach ($ttlT in $DownstreamTelemetryTtlMs) {
        foreach ($ttlC in $DownstreamCriticalTtlMs) {
          $rows += Invoke-Sim -BatchSize $batch -DownTele $dqT -DownCrit $dqC -TtlTele $ttlT -TtlCrit $ttlC
        }
      }
    }
  }
}

$sorted = $rows | Sort-Object -Property `
  @{ Expression = "neg_p99_lt_100"; Descending = $false }, `
  @{ Expression = "p99_min"; Descending = $true }, `
  @{ Expression = "p99_mean"; Descending = $true }, `
  @{ Expression = "avg_mean"; Descending = $true }

Write-Host ""
Write-Host "Top results (most stable first):"
$sorted | Select-Object -First 15 | Format-Table -AutoSize

$csvPath = Join-Path $outDirPath $OutCsv
$sorted | Export-Csv -NoTypeInformation -Encoding UTF8 -Delimiter ';' -Path $csvPath
Write-Host ""
Write-Host "Wrote: $csvPath"
} finally {
  Pop-Location
}
