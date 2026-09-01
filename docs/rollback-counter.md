# Rollback counter

`src/rollback/rollback.{h,c}` — a monotonic counter in simulated flash,
authenticated with a MAC keyed by a device secret, stored twice for power-loss
safety. In the full system the key is
`KDF(fuzzy_extract(PUF), "rollback-auth-key")`; secure boot later enforces
`fw_version >= cnt`.

## Store format

Two pages (`ROLLBACK_PAGE_BYTES` = 64), each an independent record:

| offset | field | |
|--|--|--|
| 0 | `magic` | `"RBC1"` |
| 4 | `seq` | uint32 LE — write order; the newest valid page wins |
| 8 | `cnt` | uint64 LE — the counter |
| 16 | `tag` | `SHAKE256(key ‖ "rollback/v1/tag" ‖ magic ‖ seq ‖ cnt)`, 32 B |
| 48 | pad | zero |

`tag` covers bytes `[0:16)`. The MAC is the project KDF (`rot_kdf_derive`) with
a fixed-length key and a fixed 31-byte message, so it is an unambiguous PRF.

## Operations

- **`rollback_enroll(s, key, cnt)`** — zero the store, write page 0 with
  `seq=1`. Runs once; not power-loss safe (no prior state to recover to).
- **`rollback_read(s, key, &cnt)`** — the boot path. Returns `cnt` from the
  newest MAC-valid page, or `NO_VALID_PAGE` if neither authenticates.
- **`rollback_verify(s, key, &cnt, &tampered)`** — as read, but returns
  `ERR_TAMPER` (with a bitmask of offending pages) when a page carries the
  magic but fails its MAC — a record modified in place.
- **`rollback_update(s, key, new_cnt, fault_after)`** — refuses
  `new_cnt <= current` (`ERR_MONOTONIC`); otherwise marshals `seq+1` / `new_cnt`
  and writes the **non-current** page, so the live page is untouched until the
  new one is complete. `fault_after` in `[1, 64)` truncates the write and
  erases (0xFF) the tail, modelling a power loss.

## Guarantees (from `make -C tests check-rollback`)

- **Tamper detection.** Flipping a bit of `cnt` or `tag` on the newest page
  makes it fail the MAC; `read` falls back to the older authentic page (never
  serving the forged value), `verify` reports `ERR_TAMPER`. Corrupting both
  pages yields `NO_VALID_PAGE` — boot must refuse. A value forged without the
  key (tag computed under the wrong key) is rejected.
- **Power-loss safety.** Over write-cut offsets `{1,4,8,16,20,32,40,47,48,56,63}`:
  a cut before the authenticated record ends (byte 48) durably keeps the old
  counter; at or after it the new counter is fully valid. Every case reads back
  OK with an authentic old-or-new value — never bricked, never garbage — and a
  subsequent complete update proceeds normally.
- **Integration.** `puf_sim → fuzzy_gen/rep → KDF("rollback-auth-key")`
  reconstructs the same MAC key from a 3 %-noise PUF read, and the counter
  authenticates under it.

## Known-answer coverage

Enrolled page bytes, the post-update page, and the KDF-derived key + its
enrolment tag are pinned against an independent Python implementation of the
same layout and MAC.
