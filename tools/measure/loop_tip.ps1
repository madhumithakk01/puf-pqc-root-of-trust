# Validation of a safe-N candidate: several runs in a row, each analysed when it ends (Windows PowerShell).
#
#   powershell -File tools\measure\loop_tip.ps1                 (runs 19, 20, 21)
#   powershell -File tools\measure\loop_tip.ps1 -runs 30,31,32
#
# Each run is run_tip.ps1 (fresh-demo, then the story, with loggers) followed by analyze_tip.py. The loop stops at
# the first frozen board. Output: data\results\validation\run<n>\ (local, not committed). Afterwards:
#   python tools\measure\deploy_latency.py          (Table 5.12 from the same runs)
param([int[]]$runs = @(19, 20, 21))

$sp = $PSScriptRoot
$root = (Resolve-Path "$sp\..\..").Path
foreach ($n in $runs) {
    & "$sp\run_tip.ps1" -n $n
    $code = $LASTEXITCODE
    "=== analysis run ${n}"
    python "$sp\analyze_tip.py" "$root\data\results\validation\run$n"
    if ($code -eq 3) { "FREEZE in run ${n} - stopping"; break }
}
"validation done"
