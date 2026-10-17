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

## Notes

- `build_special.sh` records the source commit and builds from the working tree; the firmware of the demo images is
  not rebuilt or replaced.
- The stage latencies of Table 5.12 were derived from the request traces of the three validation runs; the scripts for
  those runs are not part of this directory.
