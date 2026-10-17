# One validation run for a safe-N candidate (Windows PowerShell): fresh-demo, then one demo.py story, with loggers.
#
#   powershell -File tools\measure\run_tip.ps1 -n 19
#
# Steps: board.py fresh-demo; then loggers (beacon, USB console, pings from Windows and WSL to the board and
# the hotspot gateway); then the traced story (story_trace.py runs the unchanged demo.py story and logs every
# request); then the receipts of the board. A watchdog stops the run when no beacon arrives for 150 s while the
# story is running (a frozen board) and writes freeze.txt; the script then exits with code 3.
# Output goes to data\results\validation\run<n>\ (local, not committed). Hands off the board while it runs.
# Needs the board on the hotspot and the laptop on the same hotspot; analyse with analyze_tip.py.
param([int]$n)

$sp = $PSScriptRoot
$root = (Resolve-Path "$sp\..\..").Path
$run = "$root\data\results\validation\run$n"
New-Item -ItemType Directory -Force $run | Out-Null
Set-Location $root
$bs = [string][char]92
$wsp = (wsl wslpath -u ($sp.Replace($bs, '/'))).Trim()
$wroot = (wsl wslpath -u ($root.Replace($bs, '/'))).Trim()
$wrun = "$wroot/data/results/validation/run$n"

$t0 = Get-Date
python tools\demo\board.py fresh-demo 2>&1 | ForEach-Object { if ("$_".Length -lt 300 -and "$_" -match "^\[|ready|device ID|version:|floor:|address|registered|rror") { "$_" } } | Out-File "$run\fresh.log" -Encoding utf8
"{0:N0}" -f ((Get-Date) - $t0).TotalSeconds | Out-File "$run\fresh_seconds.txt"

$board = (Get-Content "$root\data\demo\device.ip").Trim()
$gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1).NextHop
"board $board, gateway $gateway" | Out-File "$run\addresses.txt"

python "$sp\offset.py" | Out-File "$run\offset_start.txt"
Start-Process python -ArgumentList "-u", "$sp\beacon.py", "$run\beacon.log" -WindowStyle Hidden
Start-Process python -ArgumentList "-u", "$sp\console.py", "$run\console.log" -WindowStyle Hidden
Start-Process python -ArgumentList "-u", "$sp\pingwin.py", "$run\pingwin.log", "board", $board, "gateway", $gateway -WindowStyle Hidden
Start-Process wsl -ArgumentList "-e", "python3", "-u", "$wsp/pingwsl.py", "$wrun/pingwsl.log", $board -WindowStyle Hidden
Start-Sleep 5
$story = Start-Process wsl -ArgumentList "-e", "python3", "-u", "$wsp/story_ts2.py", "$wrun/story.log", $wroot, "$wrun/trace.log", "$wsp/story_trace.py" -WindowStyle Hidden -PassThru
$tstart = Get-Date
$frozen = $false
while (-not $story.HasExited) {
    Start-Sleep 10
    $el = ((Get-Date) - $tstart).TotalSeconds
    $bf = Get-Item "$run\beacon.log"
    $silence = ((Get-Date) - $bf.LastWriteTime).TotalSeconds
    if ($el -gt 60 -and $silence -gt 150) { $frozen = $true; break }
}
if ($frozen) {
    $o = @()
    $o += "FREEZE detected at $(Get-Date -Format o): no beacon for $([int]$silence) s; story had run $([int]$el) s"
    $o += "--- last 15 console lines"; $o += (Get-Content "$run\console.log" -Tail 15)
    $o += "--- last 5 beacons"; $o += (Get-Content "$run\beacon.log" | Select-String BEACON | Select-Object -Last 5 | ForEach-Object { $_.Line })
    $o += "--- last 6 windows pings to the board"; $o += (Get-Content "$run\pingwin.log" | Select-String "PING board" | Select-Object -Last 6 | ForEach-Object { $_.Line })
    $o += "--- last 4 windows pings to the gateway"; $o += (Get-Content "$run\pingwin.log" | Select-String "PING gateway" | Select-Object -Last 4 | ForEach-Object { $_.Line })
    $o += "--- last 6 wsl pings to the board"; $o += (Get-Content "$run\pingwsl.log" -Tail 6)
    $o += "--- COM port (VID 0x2E8A)"; $o += (python -c "from serial.tools import list_ports; print([p.device for p in list_ports.comports() if p.vid==0x2E8A])")
    $o += "--- wifi"; $o += (netsh wlan show interfaces | Select-String " SSID", "State", "Signal" | ForEach-Object { $_.Line.Trim() })
    $o | Out-File "$run\freeze.txt" -Encoding utf8
    wsl -e bash -lc 'pkill -f story_ts2.py; pkill -f story_trace.py; pkill -f "demo.py story"; true'
}
python "$sp\offset.py" | Out-File "$run\offset_end.txt"
Start-Sleep 2
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -match 'beacon\.py|console\.py|pingwin\.py' -and $_.CommandLine -like "*$sp*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
wsl -e bash -lc 'pkill -f pingwsl.py; true'
if (-not $frozen) { wsl -e python3 "$wsp/rcp_all.py" 2>&1 | Out-File "$run\receipts_all.txt" -Encoding utf8 }
"run $n finished frozen=$frozen $(Get-Date -Format o)" | Out-File "$run\done.txt"
if ($frozen) { exit 3 }
