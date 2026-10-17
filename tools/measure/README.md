# Board measurements

Scripts that produced the hardware numbers in `docs/hardware-results.md`. Run them from the repository root.
Raw logs go to `data/results/` (local, not committed). Special firmware builds go to `data/builds/<name>/`, never to
`data/demo`. The board must be enrolled and registered from this folder (`python tools\demo\board.py fresh-demo`) and
on the same hotspot as the laptop. Hands off the board while a script runs; the wiring is unsoldered.

| Report table / figure | Script | What it does |
|---|---|---|
| Table 5.7 (PUF reconstruction), Table 5.10 (boot stages) | `restart_loop.py`, `analyze_restarts.py` | Restarts the board N times with an attestation request, records each boot report, then summarises it |
| Figure 5.4 (update on the USB console) | `fig54.ps1`, `update_v11.py`, `console_capture.py` | Shows the USB console in a window during one v1.1 update and saves the text |
| Table 5.3 (on-target self-test) | `build_special.sh`, `console_capture.py`, `restart_loop.py` | Builds the RoT with `-DROT_SELFTEST=1`; the `selftest` line is read from the console |
| Table 5.9 (PQC cost), Table 5.18 (ML-DSA-44 verify) | `build_special.sh`, `console_capture.py`, `analyze_bench.py` | Builds the bench image; its console lines are summarised |
| Table 5.14 (attacks A7 and A8) | `tools/demo/offline_attacks.py` | Offline tampering of the stored images, outcome read from the RoT console, images restored and checked |
| Table 5.10, install stage | `update_then_bootreport.py` | One update, then the boot report (shows that the install cycles are 0) |
| Validation runs for a safe-N tag (section 2 of the results) | `loop_tip.ps1`, `run_tip.ps1`, `analyze_tip.py` and their helpers | Several runs of `fresh-demo` + `demo.py story` with loggers; per run: result, times, restart delays, Wi-Fi rejoin, receipts |
| Table 5.12 (update latency per stage) | `deploy_latency.py` | Splits each vendor deploy of those runs into attest, package, push and install-and-trial |

`console_capture.py` reads the board's USB console on Windows with a fast reconnect and logs every line with a UTC
timestamp; it never invents lines that the host could not see.

## Running

Table 5.7 and Table 5.10 (about 25 minutes for 110 restarts):

    python tools\demo\board.py fresh-demo
    python tools\measure\console_capture.py data\results\table-5.7_5.10\console.log      (in a second window)
    wsl -e python3 -u tools/measure/restart_loop.py 110 data/results/table-5.7_5.10/restarts.jsonl
    python tools\measure\analyze_restarts.py data\results\table-5.7_5.10

Stop the console capture (Ctrl+C) after the loop; without `--seconds` it runs until stopped.

Figure 5.4 (about 2 minutes; take the screenshot when the window says "capture finished"):

    python tools\demo\board.py fresh-demo
    powershell -File tools\measure\fig54.ps1

Table 5.3 and Table 5.9 (WSL for the build, Windows for the flashing and the console):

    wsl -e bash tools/measure/build_special.sh
    python tools\measure\console_capture.py data\results\table-5.3\console.log --seconds 170 --lines-file data\results\table-5.3\console-lines.txt
    python tools\demo\board.py flash-rot data\builds\rot-selftest\rot-selftest.uf2

For Table 5.9, flash `data\builds\bench\bench.uf2` instead: put the board in BOOTSEL (`board.py` does it:
`python -c "import sys; sys.path.insert(0,'tools/demo'); import board; board.to_bootsel(); board.pt('load', r'data\builds\bench\bench.uf2'); board.pt('reboot', check=False)"`),
capture the console for about 110 s, then `python tools\measure\analyze_bench.py data\results\table-5.9\console-lines.txt`.
Restore the board afterwards with `python tools\demo\board.py fresh-demo` and check it with `demo.py status`
(v1.0.0, SVN 1, floor 1). Both special builds replace the RoT, so the restore must be a full `fresh-demo`.

Table 5.14: deploy v1.1 first so that the floor is 2 (`wsl -e python3 tools/measure/update_v11.py`), then

    python tools\demo\offline_attacks.py A7 --workdir data\results\table-5.14
    python tools\demo\offline_attacks.py A8 --workdir data\results\table-5.14

then `python tools\demo\board.py fresh-demo`.

Validation runs and Table 5.12 (about 7 minutes per run; hands off the board; the laptop on the board's hotspot):

    powershell -File tools\measure\loop_tip.ps1                     (three runs, numbered 19, 20, 21)
    powershell -File tools\measure\loop_tip.ps1 -runs 30,31,32      (other run numbers)
    python tools\measure\deploy_latency.py data\results\validation 30 31 32

`run_tip.ps1 -n N` does one run: `board.py fresh-demo`, then loggers, then the story. The story is run by
`story_trace.py`, which executes the unchanged `demo.py story` and only logs every connection and request (that log
gives the restart delays and Table 5.12). A watchdog stops a run when no beacon arrives for 150 s while the story
runs (a frozen board): it saves the last console lines, beacons and pings in `freeze.txt` and the loop stops.
`analyze_tip.py DIR` prints, for one run, the result, the times, the restart delay after each attest request and
install push (median and maximum), the Wi-Fi rejoin times, and whether the 9 receipts are the expected ones.
Output is in `data\results\validation\run<N>\`. The board and gateway addresses are read at run time (`device.ip` and
the default route), so the hotspot may change.

Helpers used by `run_tip.ps1`: `beacon.py` (UDP beacon log), `console.py` (USB console log), `pingwin.py` and
`pingwsl.py` (pings from Windows and from WSL), `offset.py` (Windows-WSL clock offset, measured at the start and end
of a run), `story_ts2.py` and `story_trace.py` (the traced story), `rcp_all.py` (verified receipts), `ts.py`
(timestamps). `console.py` is the logger the validation runs used; `console_capture.py` is the faster-reconnect
version used for the single-event captures.

## Notes

- `build_special.sh` records the source commit and builds from the working tree; the firmware of the demo images is
  not rebuilt or replaced.
- The clock offset between Windows and WSL drifts (0.07 s at one point, about 0.8 s at another), which is why
  `run_tip.ps1` measures it at the start and the end of each run; restart delays carry an error of about 0.3 s.
