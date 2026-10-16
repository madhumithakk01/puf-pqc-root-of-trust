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

# Board measurements for the report

Measured on 16 Oct 2026 UTC (17 Oct local time; times in the logs are UTC) on the safe-2 firmware: the images in `data/demo`, byte-identical
to the safe-1 backup, built from the committed source (section 1). The laptop tools are the working-folder tip. The
board is an RP2350 (Hazard3, RISC-V) at 150,000,000 Hz (`clk_hz` printed by the bench image). Special builds were made
from commit `1ce0219` (the firmware tree is identical to `safe-2`) into `data/builds/<name>/` and never into
`data/demo`. Raw logs are under `data/results/` (local, not committed); the scripts that produced the numbers are in
`tools/measure/` (and `tools/demo/offline_attacks.py` for Table 5.14).
After every step that changed the board's firmware it was restored with `fresh-demo` and checked with `demo.py status`:
v1.0.0, SVN 1, floor 1 each time.

## 6. Table 5.7: PUF reconstruction

110 restarts of one board (device `bf279dd7`, v1.0, floor 1), each an attestation request: the board restarts into the
root of trust, rebuilds its key from the SRAM PUF, and the laptop reads the boot report after the board is back.
All 110 restarts gave a boot report, with no error. The signed attestation report (ATR2) carried the same
`bits_corrected` and `worst_block` as the boot report in 110 of 110 restarts. The 110 restarts took 1363 s.

| Quantity (boot report) | Min | Mean | Median | Max |
|---|---|---|---|---|
| `bits_corrected` (of 3840 PUF bits) | 149 | 174.64 | 176 | 198 |
| as a fraction of 3840 bits | 3.9 % | 4.55 % | 4.6 % | 5.2 % |
| `worst_block` (block with the most corrections) | 3 | 3.65 | 4 | 5 |
| `temp_x10` (die temperature, tenths of a degree C) | 362 | 366.36 | 368 | 374 |

- `worst_block` was 3 in 45 restarts, 4 in 59 and 5 in 6. `bits_corrected` takes 40 different values between 149 and 198;
  the most frequent is 177 (11 restarts).
- `refreshes` was 1 and `reset_cause` was 7 ("other") in all 110 restarts.
- Console cross-check: the USB console showed 98 of the 110 `rot` lines (the others were printed before the host had
  re-opened the port); their `temp_x10` was 362-374 (mean 366.22), the same range as the boot report.
- `pairs_available` (spare PUF pairs beyond the 3840 used): the `enrolled` event of this board's enrollment printed
  **8240**. The stored data of another enrollment (`fa6627dc`) was inspected with `vendor_cli inspect-rotdata`: it shows
  `pairs_selected` 3840 and `pairs_available` 8199, equal to the 8199 its `enrolled` event printed. Over the five
  enrollments made in this task the `enrolled` event printed 8240, 8217, 8199, 8228 and 8222 (min 8199, mean 8221.2,
  max 8240).

Raw data: `data/results/table-5.7_5.10/restarts.jsonl`, `console.log`, `analysis.txt`.

## 7. Table 5.10: boot stages

From the same 110 restarts: the `cycles` array of the boot report. All 110 boots were attestation boots
(`last_event` 2). Cycles at 150 MHz; milliseconds = cycles / 150,000.

| Index | Stage | Min (cycles) | Mean (cycles) | Max (cycles) | Mean ms | Max ms |
|---|---|---|---|---|---|---|
| 2 | fuzzy-extractor decode | 521,120 | 523,004 | 542,460 | 3.49 | 3.62 |
| 4 | ML-DSA keygen | 4,205,163 | 4,211,356 | 4,238,606 | 28.08 | 28.26 |
| 6 | records | 89,527 | 132,428 | 136,037 | 0.88 | 0.91 |
| 7 | verify | 129,334,996 | 129,369,452 | 129,394,796 | 862.46 | 862.63 |
| 8 | install | 0 | 0 | 0 | - | - |
| 9 | attest | 12,863,561 | 22,039,872 | 44,449,210 | 146.93 | 296.33 |
| 10 | total | 147,484,396 | 156,699,418 | 179,127,884 | 1044.66 | 1194.19 |

- Index 8 is 0 on an attestation boot because no install runs on it. It is also 0 in the boot report read after a full
  v1.1 update (`last_event` 3, cycles `[0,0,522234,0,4266916,0,134636,129417239,0,0,278028232,0]`): the install runs in
  an earlier boot whose record the trial and judge boots overwrite. The install time is therefore not available from
  the boot report; the wall-clock "install and trial" stage is in Table 5.12. See section 12.2.
- Indices 0, 1, 3, 5 and 11 were 0 in every boot report (the firmware does not report those stages).
- Index 9 (attest) varies from 12.9 M to 44.4 M cycles between boots. Stages 2, 4 and 7 vary by 4.1 %, 0.8 % and 0.05 % (max minus min, over the mean). Stage 6 (records) has one low value of 89,527 cycles; its other 109 values are 130,101-136,037 (median 132,789).
- Index 4 (4.21 M cycles, 28.1 ms) matches the 4.23 M cycles the bench image measures for key derivation (Table 5.9).

Raw data: `data/results/table-5.7_5.10/restarts.jsonl`, `after-update-bootreport.txt`.

## 8. Figure 5.4: one v1.1 update on the USB console

The board's USB console (115200 baud) was read from the laptop during over-the-air updates to v1.1. The USB port
disappears at every reset and Windows needs about 0.25 s to open it again, so lines printed just before or just after a
reset can be missed; nothing below is reconstructed. Three updates were captured:

- **Attempt 1** (shown in the terminal window used for the screenshot): v1.0 to v1.1, SVN 1 to 2, floor 1 to 2, slot A to
  B, committed, 39.6 s. Lines seen: `rot`, `install` (trial 1), `rot`, `trial` (committed 1), then `wifi join failed,
  retrying` and `ip`. Not seen: both `chain` events and the application's trial line.
- **Attempt 2** and **attempt 3**: v1.1 installed over v1.1 (SVN 2 to 2), committed, 45.1 s and 41.3 s. Both caught the
  `chain` events. Attempt 2, verbatim (including the lines of the preceding restart):

```
{"ev":"rot","build":"b91f559929510259372","cause":7,"refreshes":1,"temp_x10":374}
{"ev":"install","refused":0,"reason":0,"trial":1}
{"ev":"chain","slot":0,"svn":2,"floor":2,"bits":163,"worst":5,"trial":1}
{"ev":"chain","slot":0,"svn":2,"floor":2,"trial":1}
{"ev":"rot","build":"b91f559929510259372","cause":7,"refreshes":1,"temp_x10":374}
{"ev":"trial","committed":1,"reason":0,"svn":2,"floor":2}
{"ev":"chain","slot":0,"svn":2,"floor":2,"bits":181,"worst":4,"trial":0}
{"ev":"chain","slot":0,"svn":2,"floor":2,"trial":0}
wifi join failed, retrying
ip 192.168.43.134
```

  Attempt 3 had the same lines except for the `rot` line of the trial-judging boot, which was not caught.
- Each `chain` event was printed as two lines, the first with `bits` and `worst`, the second without them.
- The application's own trial line (`trial: bpm_x10=... live=... -> reboot`) was not received in any of the three attempts.
  The application prints it, flushes stdio and resets 10 ms later (`firmware/app/main.c:234-236`; section 12.3).
- The `build` field in the `rot` line is the build id `b91f559929510259372` of the tested images.
- Why the application's trial line is missing: section 12.3.

So the expected sequence `rot`, `install`, `chain` (trial 1), the application's trial line, `trial` (committed 1),
`chain` (trial 0) was seen in full except for the application's trial line (attempt 2), and attempt 1 saw `rot`,
`install` and `trial` only. Raw data: `data/results/figure-5.4/` (`console.log`, `console-lines.txt`, `attempt2.*`,
`attempt3.*`).

## 9. Table 5.3: on-target self-test

The RoT was built with `-DROT_SELFTEST=1` into `data/builds/rot-selftest/` (commit `1ce0219`, `rot-selftest.uf2`
SHA-256 `7ec12eb372f07dcadbfead75821a00c0e875ab56cc78c7ad86a96d5ff228df49`), flashed over the RoT of the enrolled board
(stored data kept), and the `selftest` event was read from the USB console at its first boot and at 5 further RoT boots
(attestation restarts). All 6 lines had `failed_mask` 0 (every known-answer check passed). The five cycle counts are, in
the order of `rot_selftest.h`:

| Check | Boots | Min (cycles) | Mean (cycles) | Max (cycles) | Mean ms |
|---|---|---|---|---|---|
| SHAKE256("abc") | 6 | 73,201 | 75,078 | 76,721 | 0.50 |
| ML-DSA-44 verifies a host signature | 6 | 2,893,697 | 2,896,463 | 2,900,127 | 19.31 |
| ML-DSA-44 rejects a signature with one bit flipped | 6 | 2,836,368 | 2,838,084 | 2,840,601 | 18.92 |
| ML-KEM-512 decapsulates a host ciphertext | 6 | 1,201,975 | 1,204,344 | 1,206,247 | 8.03 |
| keys from the fixed UDS match the host fingerprints | 6 | 4,231,347 | 4,232,922 | 4,234,734 | 28.22 |

The five checks together take 11,246,892 cycles on average (74.98 ms; range 11,241,641-11,250,393). The first line:
`{"ev":"selftest","failed_mask":0,"cycles":[73284,2900127,2836419,1205829,4234734]}`. Restored afterwards with
`fresh-demo` (device `0e49611f`, v1.0.0, SVN 1, floor 1). Raw data: `data/results/table-5.3/`.

## 10. Table 5.9: PQC cost on the board (and the ML-DSA-44 verify time for Table 5.18)

The bench image (`data/builds/bench/bench.uf2`, commit `1ce0219`, SHA-256
`b32858f63e4d07c5b820064f92b9826f163f8f1136a07508c44cb2d0c589ca62`) was flashed and its console read for 110 s: it runs
every operation once per pass and repeats the pass. 21 complete passes were read, the ML-KEM shared secrets agreed in all
21, and `clk_hz` was 150,000,000. Cycles and retired instructions (instret) per operation; ms = cycles / 150,000:

| Operation | Passes | Cycles min | Cycles mean | Cycles max | ms mean (min-max) | Instret mean | Instret per cycle |
|---|---|---|---|---|---|---|---|
| SHAKE256, 1 KB | 21 | 190,011 | 193,918 | 216,211 | 1.29 (1.27-1.44) | 148,660 | 0.77 |
| Key derivation (ML-DSA + ML-KEM + KDF) | 21 | 4,220,028 | 4,227,691 | 4,251,851 | 28.18 (28.13-28.35) | 3,810,197 | 0.90 |
| ML-DSA-44 sign (64-byte message) | 21 | 4,072,090 | 6,822,388 | 15,894,626 | 45.48 (27.15-105.96) | 5,997,600 | 0.88 |
| **ML-DSA-44 verify (64-byte message)** | 21 | 2,856,606 | 2,862,575 | 2,867,671 | **19.08 (19.04-19.12)** | 2,555,092 | 0.89 |
| ML-KEM-512 encapsulate | 21 | 1,021,097 | 1,023,767 | 1,028,004 | 6.83 (6.81-6.85) | 869,597 | 0.85 |
| ML-KEM-512 decapsulate | 21 | 1,165,095 | 1,168,299 | 1,171,131 | 7.79 (7.77-7.81) | 1,011,358 | 0.87 |

- **For Table 5.18:** ML-DSA-44 verify takes 2,862,575 cycles on average, **19.08 ms** (range 19.04-19.12 ms, 21 passes).
  The self-test measured 2,896,463 cycles (19.31 ms) for the same operation on a different message.
- Signing varies between 27 and 106 ms from pass to pass; every other operation varies by under 1.5 %, apart from the
  slowest SHAKE pass (216,211 cycles, 11 % above the mean).
- Restored afterwards with `fresh-demo` (device `fa6627dc`, v1.0.0, SVN 1, floor 1). Raw data: `data/results/table-5.9/`.

## 11. Table 5.14: attacks A7 and A8 on the board (offline tampering of the stored images)

The tool `tools/demo/offline_attacks.py` (branch `exp/offline-attacks`, commit `aca5a0f`, from `safe-2`, tools only,
not pushed) performs the same tampering as scenarios A7 and A8 of `tools/attacker/scenarios.py` through
`tools/flash/pico_ops.py`, reads the outcome from the RoT's USB console (the RoT has no network in SAFE mode), and writes
the images back afterwards. Both attacks started from the same state: v1.1.0, SVN 2, floor 2, active slot B, both slots
good (`slot_status` `[1,1]`), receipt sequence 1. Before each attack the whole flash of both slots and the `rot_data`
region were saved; the SHA-256 of the three saved regions was identical for A7 and A8, so the restore after A7 returned
the flash to the same bytes.

| | A7: bit flipped in the active image | A8: both slots replaced by the genuine v1.0 image |
|---|---|---|
| Tampering | genuine v1.0 image written to slot A; bit 0 of byte 5000 flipped in slot B (active) | genuine, correctly signed v1.0 image written to slot A and slot B |
| Expected by design | SAFE mode, `NO_VALID_IMAGE`, image reason `IMG_BAD_SIGNATURE` (9) | SAFE mode, `NO_VALID_IMAGE`, image reason `IMG_BELOW_FLOOR` (10) |
| **Observed on the console** | `slot_refused` slot 1 reason 9; `slot_refused` slot 0 reason 10; `safe` `NO_VALID_IMAGE`, image reason 9 | `slot_refused` slot 1 reason 10; `slot_refused` slot 0 reason 10; `safe` `NO_VALID_IMAGE`, image reason 10 |
| As designed | yes | yes |
| Time from the first `rot` line to the first `safe` event | 0.87 s | 0.87 s |
| `safe` events in the 30 s window (2 s period) | 14 | 14 |
| Images after restore, compared with the snapshot | slot A and slot B byte-identical | slot A and slot B byte-identical |
| `rot_data` bytes changed by the attacked boot | 0 | 0 |
| Board after restore | v1.1.0, SVN 2, floor 2, slot B, receipt sequence 1 (same as before) | same |

Console of A7, verbatim: `{"ev":"rot","build":"b91f559929510259372","cause":7,"refreshes":1,"temp_x10":351}`,
`{"ev":"slot_refused","slot":1,"reason":9}`, `{"ev":"slot_refused","slot":0,"reason":10}`,
`{"ev":"safe","reason":"NO_VALID_IMAGE","image_reason":9}`. In A7 the tampered image is refused for its signature
(reason 9) and the genuine old image in the other slot for the floor (reason 10); the SAFE event reports the first.
The board stayed in SAFE mode until it was rebooted from BOOTSEL by the tool. The `rot_data` region was byte-identical
before and after the attacked boot, so no counter or journal changed. Raw data: `data/results/table-5.14/`
(`A7-result.json`, `A8-result.json`, the saved regions and the console logs).

## 12. Notes and limits of the board measurements

### 12.1 What the boot "verify" stage (Table 5.10, index 7, 862 ms) contains

The stage times the loop in `src/rot/rot_boot.c` that calls `rot_slot_verify` on the active slot (the trial slot during a
trial). On a normal boot the first slot passes, so one image is verified. `rot_slot_verify` (`src/rot/rot_slot.c`) does
two things with the same bytes:

1. `secure_boot_check` runs the ML-DSA-44 verification over `image[0 : 24 + body_len]` (`src/secure_boot/secure_boot.c`,
   the `crypto_sign_verify` call). ML-DSA hashes the whole message once to form its message representative, so this
   pass reads every byte of the signed region.
2. It then computes the image digest, SHAKE256 over a label followed by the same `24 + body_len` bytes, a second full
   pass.

Sizes (v1.1 image, `data/demo/v1_1_0.sbi.bin`): the file is 380,868 bytes; the header gives `body_len` 378,420 and the
signature is 2,420 bytes. The hashed region is therefore 24 + 378,420 = 378,444 bytes = 369.57 KiB, per pass. The
v1.0 and v1.2 images have the same size.

Expected time from the bench (Table 5.9): SHAKE256 on 1 KB takes 193,918 cycles, 1.29 ms (1.2928 ms). Per pass:
369.57 KiB x 1.29 ms = 476.8 ms; two passes: 953.5 ms. The ML-DSA-44 signature check itself (the bench, a 64-byte
message) is 2,862,575 cycles = 19.08 ms. Expected total: 953.5 + 19.08 = 972.6 ms.

Measured: 129,369,452 cycles = 862.46 ms on average (range 862.23-862.63 ms over the 110 boots), which is 88.7 % of
the expected value. Of the stage, the signature mathematics is 19.08 ms (2.2 %); the rest, 843.4 ms, is hashing the image
twice (421.7 ms per pass, 1.14 ms per KiB). The 1 KB benchmark therefore overstates the per-KiB cost of a 370 KiB message
by about 12 %. A likely cause is the fixed cost of one call (the padded final block and the set-up), which a long message
amortises; this was not tested, and the per-KiB cost of a long message was not measured separately on the board.

The stage grows with the image size, and a boot that refuses the first slot also verifies the second (in Table 5.14 the
two refused slots took 0.87 s from the first `rot` line to the SAFE event).

### 12.2 Why install shows 0 in the boot report (Table 5.10, index 8)

The boot report holds the cycle counts of the most recent boot only. The install runs in an earlier boot: the
application writes a mailbox request and resets, and the RoT writes the new image in that boot. The trial boot and
then the judging boot that follow overwrite the report. After a full update the report is that of the judging boot
(`last_event` 3, index 8 = 0, index 7 = 129,417,239 cycles, index 10 = 278,028,232 cycles). Index 8 was also 0 in all 110
attestation boots, which have no install. The time of an install is the wall-clock "install and trial" stage of Table
5.12 (12.1-22.1 s: restart into the RoT, the checks, the write, the trial boot, the decision and the hotspot rejoin).

### 12.3 The application's trial line on the USB console (Figure 5.4)

The application prints `trial: bpm_x10=... live=... -> reboot`, flushes stdio and calls `watchdog_reboot(0, 0, 10)`
(`firmware/app/main.c:234-236`): the reset follows the line by about 10 ms. The line was not received in any of the
three captured updates, although in attempt 1 the USB port was open during the trial (about 0.8 s). The most likely
reason is the reset 10 ms after the line, which tears the USB connection down before the host reads what was queued;
this was not tested. The line is not shown in Figure 5.4 and was not reconstructed; the outcome of the trial is visible
anyway in the next RoT event, `{"ev":"trial","committed":1,...}`. No firmware change was made to flush it earlier.

### 12.4 Temperature range of the PUF figures (Table 5.7)

The 110 restarts ran with a die temperature of 36.2-37.4 degrees C (`temp_x10` 362-374, mean 36.64), in one
sitting of 23 minutes (one restart every 12 s), with the board powered over USB. The `bits_corrected` and
`worst_block` figures are for that range only. The board was not heated or cooled, and no restart was measured
outside it; other boot reports taken during these measurements show die temperatures of 33.9-38.0 degrees C, but they are single
readings and do not support any statement about the dependence of the error rate on temperature.

## 13. Summary of what was restored and what was not seen

- After every firmware-changing step the board was restored with `fresh-demo` and checked: v1.0.0, SVN 1, floor 1
  (devices `0e49611f`, `fa6627dc`, `a7fd9b53`, `4264da4d` in turn). It is in that state now.
- No freeze, no wrong security outcome and no failed restore occurred in these measurements.
- Not observed: the application's trial line on the USB console (Figure 5.4), and install-stage cycles in the boot
  report (Table 5.10 index 8).
