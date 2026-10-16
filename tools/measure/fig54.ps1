# Figure 5.4: one v1.1 update with the board's USB console shown in a window (Windows PowerShell).
#
#   powershell -File tools\measure\fig54.ps1
#
# Opens a window that prints the board's USB console (for a screenshot), then runs one v1.1 update through
# WSL (tools/measure/update_v11.py). The board must be running, registered and reachable; for a v1.0 to v1.1
# update run `python tools\demo\board.py fresh-demo` first. The saved text goes to data\results\figure-5.4\.
# Lines the host cannot see (printed just before a USB reset) are not shown and not invented.

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$out = "$root\data\results\figure-5.4"
New-Item -ItemType Directory -Force $out | Out-Null
Remove-Item "$out\console-lines.txt", "$out\console.log" -ErrorAction SilentlyContinue
$cap = "$PSScriptRoot\console_capture.py"
$cmd = "`$Host.UI.RawUI.WindowTitle='Board USB console - v1.0 to v1.1 update'; " +
       "Write-Host 'USB console of the board (115200 baud) during an over-the-air update to v1.1' -ForegroundColor Cyan; " +
       "Write-Host ''; python '$cap' '$out\console.log' --seconds 100 --show --lines-file '$out\console-lines.txt'; " +
       "Write-Host ''; Write-Host '--- capture finished; close this window when done ---' -ForegroundColor Cyan"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $cmd
Start-Sleep 4
$t0 = Get-Date
wsl --cd $root -e python3 -u tools/measure/update_v11.py 2>&1 | Tee-Object -FilePath "$out\update.out"
"update finished after {0:N0} s" -f ((Get-Date) - $t0).TotalSeconds
