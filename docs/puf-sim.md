# Simulated PUF

`src/puf/puf_sim.{h,c}` — a stand-in for a silicon PUF so the fuzzy extractor
and everything above it can be built and characterised before hardware exists.
**Not a security primitive.** It does not commit to SRAM-PUF vs RO-PUF or any
particular part; it only reproduces the two behaviours the upper layers care
about: a device-unique raw fingerprint, and bit error on each read.

## Model

| call | meaning |
| --- | --- |
| `puf_sim_response(id, out, n)` | clean fingerprint = `SHAKE256("puf-sim/response/v1" \|\| LE32(id))` |
| `puf_sim_response_noisy(id, ber_ppm, noise, noise_len, out, n)` | clean response with each bit flipped independently with probability `ber_ppm / 1e6`; flip pattern = `SHAKE256("puf-sim/noise/v1" \|\| LE32(id) \|\| noise)` |
| `puf_sim_hamming(a, b, n)` | differing bits |

- **Deterministic**: a given `id` always gives the same clean bytes; a given
  `(id, ber_ppm, noise)` always gives the same noisy bytes. Vary `noise` to
  model successive power-ups.
- **Uniform**: distinct ids are ~50 % apart (XOF output); a shorter request is
  a prefix of a longer one.
- **BER**: per bit, a 32-bit draw `d` from the stream flips the bit when
  `(d * 1e6) >> 32 < ber_ppm`, i.e. flip probability `ber_ppm / 1e6`
  (`ber_ppm` clamped to 1e6; `0` returns the clean response).

## Tests (`make -C tests check-puf`)

`tests/puf/test_puf_sim.c`:

- known answers for the clean response (independently generated with CPython
  `hashlib.shake_256`) and for one noisy sample;
- clean response is deterministic and, over 16 ids / 120 pairs, 40-60 % apart;
- `ber_ppm = 0` returns the clean response; a fixed `(id, ber, noise)` is
  reproducible; a different `noise` gives a different flip set;
- **BER is measurable and tracks the setting**: over 128 simulated power-ups
  x 512 bits per point, the observed flip rate matches the configured rate for
  `ber_ppm` in {0, 1 %, 5 %, 10 %, 20 %} within +/- 0.006.
