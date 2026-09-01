# Fuzzy extractor

`src/fuzzy/fuzzy_extractor.{h,c}` — turns a noisy PUF response into a stable
key. Code-offset construction: a repetition-code **secure sketch** for error
correction, then a **SHAKE256 extractor**.

## Construction

```
Gen(w):                                   Rep(w', P):
  m   <- random, `blocks` bits              c'    = w' XOR P            (= c XOR e)
  c   = repeat each bit of m, `rep` times   for each rep-block:
  P   = w XOR c                               m_hat = majority vote
  R   = SHAKE256("fuzzy/v1/extract" || w)   c_hat = repeat(m_hat, rep)
  return (P, R)                             w_hat = c_hat XOR P
                                            return SHAKE256("fuzzy/v1/extract" || w_hat)
```

`Rep` returns `Gen`'s `R` exactly when every repetition block sees at most
`floor(rep/2)` bit errors. Bits are LSB-first within each byte; block `b` is
bits `[b*rep, b*rep+rep)`.

## Parameters

`fuzzy_params { blocks, rep }`; `rep` odd. PUF bits consumed = `blocks * rep`
(must be a byte multiple, `<= FUZZY_MAX_RESPONSE_BYTES*8`). Helper data `P` is
the same length as `w`.

**Entropy.** For a full-entropy `w`, the helper leaks at most
`blocks*rep - blocks` bits, leaving `>= blocks` bits in `w` given `P`. Choose
`blocks >= 128` for a 128-bit key. The default characterised here is
**`blocks = 128`, `rep = 15`** — 240 bytes of PUF response, 240 bytes of helper.

## Reproduction success rate

Empirical over 200 trials per point (simulated PUF at each bit-error rate),
against the analytic `(1 - P_block)^blocks` where `P_block` is the binomial tail
`P(>= ceil(rep/2) of rep bits in error)`. From `make -C tests check-fuzzy`:

| BER | rep=5 (80 B) | rep=9 (144 B) | rep=15 (240 B) |
|--:|--:|--:|--:|
| 0 %  | 1.000 | 1.000 | 1.000 |
| 1 %  | 1.000 | 1.000 | 1.000 |
| 2 %  | 0.995 | 1.000 | 1.000 |
| 5 %  | 0.850 | 1.000 | 1.000 |
| 8 %  | 0.505 | 0.955 | 1.000 |
| 10 % | 0.320 | 0.890 | 0.995 |
| 12 % | 0.145 | 0.720 | 0.990 |
| 15 % | 0.025 | 0.465 | 0.960 |
| 20 % | 0.000 | 0.070 | 0.605 |
| 25 % | 0.000 | 0.000 | 0.110 |

`rep = 15` reproduces the key with probability `>= 0.99` up to ~12 % BER and
`>= 0.96` at 15 %, then falls off past ~20 %. Larger `rep` shifts the curve
right at a linear cost in PUF bits and helper size. This is the input for
sizing the PUF region once a real per-cell error rate is known.

## Tests (`make -C tests check-fuzzy`)

`tests/fuzzy/test_fuzzy.c`: known-answer `helper` / `key` vs an independent
Python implementation of the same construction; no-noise round trip;
correction capacity (7 errors in a `rep=15` block reproduce the key, 8 do
not); parameter-error rejection; and the success-rate sweep above with an
analytic cross-check (empirical within 0.08 of the model at every point).

## Later

A BCH code in place of the repetition code corrects the same error fraction
with far fewer PUF bits. The API (`fuzzy_gen` / `fuzzy_rep` over `w` and `P`)
does not change; only the sketch's encode/decode does.
