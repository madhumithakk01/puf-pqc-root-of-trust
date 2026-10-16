# Hardware results

Measurements from the real board (Raspberry Pi Pico 2 W, RP2350 RISC-V, MAX30102 sensor on unsoldered wiring)
on a phone hotspot, 16-17 Oct 2026. Only measured values are given. Times are wall-clock seconds on the laptop.
All runs use the images in `data/demo` (same SHA-256 as the safe-1 backup) and the laptop tools at `1990cd7`
(tag `safe-2`), unless a section says otherwise.

How a run was made: `python tools\demo\board.py fresh-demo` (wipe, load the root of trust, enroll, register,
provision v1.0, wait for the board), then `demo.py story` (9 steps), with a beacon logger (UDP 7001), a USB console
logger that reconnects after every restart, and ping loggers (Windows and WSL to the board, Windows to the hotspot
gateway) running. Restart delays are measured from a request on the WSL side to the board's USB port dropping on the
Windows side; the Windows/WSL clock offset (about 0.8 s) was measured at the start and end of each run, so those
delays carry an error of about 0.3 s.

## 1. Rebuild check: the safe-1 source gives the tested firmware

A clean clone at tag `safe-1` (commit `62af3c8`) was built with `tools/demo/build_all.sh` using the backed-up vendor
keys (no new keys), and compared with the images that passed the story on 14 and 15 Oct (build id `b91f559`; the file times show they were
built before the later commits 705256a, 771f49e and 04f977d, so from a working tree with uncommitted changes).

| Part | Result |
|---|---|
| Root of trust (`rot.uf2`, flattened by flash address) | same size (104704 bytes) and load address (0x10000000); 19 bytes differ in 3 ranges, all the build id and the build date |
| App images v1.0.0, v1.1.0, v1.2.0: SBI1 header | identical |
| App images: APM1 manifest (4072 bytes) | identical once the 20-byte build id field is masked |
| App images: firmware (`app.bin`, 374348 bytes each) | 1 byte differs in each, a date digit ("Oct 14" against "Oct 16") |
| App images: signature (2420 bytes) | different, as expected |

No other difference. The firmware in the tested images is the firmware built from the committed source at `safe-1`.
Full output: `REBUILD-CHECK.txt` in the safe-1 backup folder.

## 2. Validation runs 19-21 (tag safe-2)

Three runs in a row, each from a fresh board.

| | Run 19 | Run 20 | Run 21 |
|---|---|---|---|
| `fresh-demo` time | 59 s | 59 s | 56 s |
| Story result | 9 of 9 | 9 of 9 | 9 of 9 |
| Story time | 310 s | 314 s | 309 s |
| Step times (s), steps 1-9 | 12 36 40 30 31 30 58 31 40 | 12 38 40 31 31 31 56 32 41 | 12 38 39 30 30 31 57 31 40 |
| Network hiccups / sensor retries | 0 / 0 | 0 / 0 | 0 / 0 |
| Restart after an attest request, median (max), n=9 | 0.5 s (0.9) | 0.5 s (0.7) | 0.4 s (1.0) |
| Restart after the install push, median (max), n=8 | 0.5 s (0.8) | 0.5 s (0.6) | 0.4 s (0.6) |
| Wi-Fi rejoin (RoT line to `ip` line), median (max) | 8.1 s (19.4), n=17 | 8.5 s (19.5), n=18 | 8.0 s (19.5), n=18 |
| "wifi join failed, retrying" lines | 18 | 18 | 18 |
| Longest silence between beacons | 23 s | 22 s | 23 s |
| Hotspot gateway pings (timeouts) | 319 (0) | 328 (0) | 318 (0) |
| Receipts | 9, chain valid | 9, chain valid | 9, chain valid |
| Receipts with a wrong security outcome | none | none | none |

Pooled over the three runs: restart after an attest request n=27, median 0.5 s, range 0.3-1.0 s; restart after the
install push n=24, median 0.5 s, range 0.3-0.8 s. The story takes 311 s on average. Wi-Fi rejoin medians are 8.0-8.5 s
per run and the slowest rejoin in any run is 19.5 s. The application prints about one "wifi join failed, retrying" line
per restart (18, 18 and 18 lines for 17, 18 and 18 restarts); the first join attempt fails about 4 s after the
application starts and the next one succeeds.

Receipts in each run, in order (all three runs identical): #1 COMMITTED (SVN 1 to 2, floor 1 to 2); #2 ROLLED_BACK,
health check failed: heart rate (2 to 3, floor stays 2); #3 REFUSED, SVN below floor (2 to 1); #4 REFUSED, package
authentication failed (digest); #5 REFUSED, unknown signer (2 to 0); #6 COMMITTED (the genuine capture for the replay
attack); #7 REFUSED, stale nonce; #8 REFUSED, not for this device; #9 COMMITTED (the genuine capture for the
eavesdropping check). The floor ends at 2 in every run and never falls.

## 3. Update latency per deploy step (Table 5.12)

Stages of one deploy (`vendor_lib.deploy`), taken from the request trace of runs 19-21 for the three vendor deploys
in each story (steps 2, 3 and 4). Mean (range) in seconds over the 3 runs, n=3 per row:

| Deploy | Attest | Package | Push | Install and trial | Total |
|---|---|---|---|---|---|
| v1.1 accepted (committed, floor 1 to 2) | 12.08 (12.06-12.10) | 0.14 (0.14-0.14) | 5.65 (5.41-5.84) | 19.59 (18.16-20.32) | 37.46 (36.10-38.33) |
| v1.2 rolled back (heart rate) | 11.51 (10.25-12.18) | 0.12 (0.08-0.14) | 5.78 (5.63-5.87) | 22.11 (22.10-22.13) | 39.52 (38.38-40.26) |
| v1.0 refused (SVN below floor) | 12.09 (12.08-12.09) | 0.11 (0.09-0.12) | 6.15 (5.93-6.52) | 12.09 (12.08-12.10) | 30.44 (30.23-30.81) |
| All 9 deploys | 11.89 (10.25-12.18) | 0.12 (0.08-0.14) | 5.86 (5.41-6.52) | 17.93 (12.08-22.13) | 35.80 (30.23-40.26) |

Per-deploy values (runs 19, 20, 21), v1.1 accepted: attest 12.10, 12.07, 12.06; package 0.14, 0.14, 0.14; push 5.70,
5.41, 5.84; install and trial 18.16, 20.32, 20.28.

How the stages are bounded:
- Attest: from the start of the attestation request to the reply that carries the vendor's nonce. It includes the
  board's restart into the root of trust (0.3-1.0 s after the request), the rejoin of the hotspot, and a deliberate
  quiet period of 2.0 s after the request (`QUIET_S` in `tools/demo/quiet_vendor.py`).
- Package: from that reply to the start of the push connection. It includes verifying the attestation report and
  building the signed, encrypted package with `vendor_cli`.
- Push: connection start to the end of the install request; the package is 94 chunks of 4096 bytes (384260 bytes).
- Install and trial: end of the install request to the first status reply that shows the new receipt and no trial in
  progress. This covers the restart into the root of trust, the checks, the write into the inactive slot, the trial
  boot with the health self-test, the commit or rollback decision, and the rejoin of the hotspot.
- Total: attest start to the end of install and trial. Fetching and verifying the receipts afterwards is not included.
- Resolution: the board is polled every 2 s while it restarts, and each failed connection attempt can last up to 3 s, so
  the install and trial figures are resolved to about 2 s (the values cluster at 12.1, 18.2, 20.3 and 22.1 s).

The refused deploy has the shortest install and trial stage (12.1 s in all three runs): the root of trust refuses the
package before anything is written to a slot, so there is no trial boot. The rolled-back deploy is the longest (22.1 s):
it adds the trial boot and the rollback decision to a normal install.

## 4. Restart delay on the earlier code (cause of the unreliable stories)

On safe-1 code the story was unreliable. In the restore drill (fresh board, safe-1 tools, 17 Oct) 1 of 9 steps passed:
25 of 26 attempts saw the board restart more than 8 s after the attest request or install (median of those 34.5 s,
maximum 41.0 s), against 0.3-1.0 s on the safe-2 tools. Wi-Fi rejoin was the same in both (median 8.0 s, maximum 19.3 s),
and the hotspot gateway answered all 1212 pings in the drill, so the delay is not in the radio link.

Evidence for the cause, from a traced run on the unfixed tools (run 9): the board's application schedules its restart
300 ms after the last accepted request, and `firmware/app/main.c:314` re-arms that timer for every later frame while the
restart is pending (read from the source; the firmware was not changed to test it). The vendor tool polled the board about 7 times a second right after the request. Predicting the
restart as "the first gap of at least 1 s in traffic to the board, plus 0.3 s" matched the observed restart within 2 s in
17 of 18 attempts (median error 0.2 s); a gap of 0.3 s predicted it in 6 of 18. During the delays of run 5, a native
Windows probe (one connection and HELLO per second) got 1129 answers in 1160 attempts, and in 12 of the 17 delay windows
with probes the slowest answer took under 100 ms; the WSL sockets showed no retransmissions. The tools in
`tools/demo/quiet_vendor.py` stay silent for 2 s after the request and poll every 2 s afterwards; the firmware was not
changed.

## 5. Open issue: board freeze in run 18

One run on the quiet-vendor tools ended with the board unresponsive (run 18, the third of three validation runs on
17 Oct, before runs 19-21; the code was the content that became `b83c5f5` and `1990cd7`, still uncommitted at the time).
The cause is not known. Runs 19-21 did not show it.

Evidence (device `d017971f`, v1.0 at the start of the run, times UTC on 16 Oct as logged):
- Steps 1-5 passed in 20, 40, 51, 42 and 43 s. Step 6 (attack A2) started at 19:38:22.
- The board restarted at 19:38:36 (USB drop), the root of trust ran (`rot` line at 19:38:38.272), the application printed
  "wifi join failed, retrying" at 19:38:43.070 and `ip 192.168.43.134` at 19:38:46.457.
- One beacon arrived, at 19:38:46.349. No further beacon arrived: 56 beacons in the whole run, none after 19:38:47.
- The USB console printed nothing after the `ip` line (0 events from 19:38:46.5 to the end of the logging at 20:15), and
  the USB port did not drop: no reset, no watchdog restart.
- Ping to the board from Windows: 104 of 221 answered before 19:38:40, 0 of 2198 after. From WSL: 0 of 2197 answered in
  19:38:40-20:15:17. The hotspot gateway answered 2198 of 2198 from Windows, and the laptop stayed on the hotspot, so the
  network and the laptop were up.
- Steps 6-9 failed after 480, 576, 567 and 570 s (three attempts each, every attempt ending in "no report carrying the
  verifier's nonce arrived" or "device did not reach the expected state; last status None"). The receipt listing at
  the end of the story could not be fetched (OSError). The receipts of steps 1-5 were written before the freeze.
- After the run the board still showed as `COM4` (VID 0x2E8A) with no console output and no ping answer. After a power
  cycle the manual reset worked (restore drill), and `fresh-demo` worked in run 19.

Not known: whether the freeze is in the application after the Wi-Fi join (the lwIP stack stopped answering and the beacon
stopped), whether the unsoldered sensor wiring played a part, or whether it relates to the restart handling above.
Frequency: 1 freeze in the 6 runs with a working sensor on these tools (runs 16-21). Runs 13-15 ended early on a sensor that
was not answering and are not counted. No freeze was seen in the logged runs on the earlier tools (runs 1-5 and 9, and the restore drill).
The rate is not established.

Recovery: unplug and replug the USB cable, then run `python tools\demo\board.py fresh-demo`.
