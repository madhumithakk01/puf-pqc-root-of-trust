/*
 * Footprint spike harness. One operation per image, selected by -DOP_<name>.
 *
 * Two fixture modes:
 *   -DFIX_RUNTIME : op_setup() builds valid inputs at run time (used for the
 *                   stack high-water-mark image, run under QEMU).
 *   (default)     : inputs are left zero; the operation is still linked so
 *                   `size` sees its code, but the image is not executed.
 *
 * Report lines on the UART:
 *   op=<name>
 *   fix=<runtime|static>
 *   result=<ok|fail>
 *   stack_used_bytes=<n>
 */

#include "rt/rt.h"

#include "randombytes.h"

#include <stddef.h>
#include <stdint.h>

#if defined(OP_MLDSA_KEYGEN) || defined(OP_MLDSA_SIGN) || defined(OP_MLDSA_VERIFY)
#define SCHEME_MLDSA 1
#include "api.h" /* PQCLEAN_MLDSA44_CLEAN_* */
#define PK_BYTES  PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES
#define SK_BYTES  PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES
#define SIG_BYTES PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES
#elif defined(OP_MLKEM_KEYGEN) || defined(OP_MLKEM_ENCAPS) || defined(OP_MLKEM_DECAPS)
#define SCHEME_MLKEM 1
#include "api.h" /* PQCLEAN_MLKEM512_CLEAN_* */
#define PK_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define SK_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#define CT_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define SS_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
#elif defined(OP_BASELINE)
/* no scheme */
#else
#error "define one of OP_MLDSA_{KEYGEN,SIGN,VERIFY}, OP_MLKEM_{KEYGEN,ENCAPS,DECAPS}, OP_BASELINE"
#endif

#ifdef FIX_RUNTIME
#define FIX_NAME "runtime"
#define ITERS 16
#else
#define FIX_NAME "static"
#define ITERS 1
#endif

#define MSGLEN 32
#define U __attribute__((unused)) /* a given op touches only some of these */

#ifdef SCHEME_MLDSA
static U uint8_t pk[PK_BYTES];
static U uint8_t sk[SK_BYTES];
static U uint8_t sig[SIG_BYTES];
static U uint8_t msg[MSGLEN];
static U size_t  siglen;
#endif
#ifdef SCHEME_MLKEM
static U uint8_t pk[PK_BYTES];
static U uint8_t sk[SK_BYTES];
static U uint8_t ct[CT_BYTES];
static U uint8_t ss_a[SS_BYTES];
static U uint8_t ss_b[SS_BYTES];
#endif
#ifdef OP_BASELINE
static U uint8_t scratch[MSGLEN];
#endif

static int op_setup(void)
{
#ifdef FIX_RUNTIME
#if defined(OP_MLDSA_SIGN)
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
#elif defined(OP_MLDSA_VERIFY)
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
        return 1;
    }
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, MSGLEN, sk);
#elif defined(OP_MLKEM_ENCAPS)
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
#elif defined(OP_MLKEM_DECAPS)
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk) != 0) {
        return 1;
    }
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss_a, pk);
#endif
#endif
    return 0;
}

static int op_once(int it)
{
    (void)it;
#if defined(OP_MLDSA_KEYGEN)
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
#elif defined(OP_MLDSA_SIGN)
    msg[(unsigned)it % MSGLEN] ^= 0x5a;
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, MSGLEN, sk);
#elif defined(OP_MLDSA_VERIFY)
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, MSGLEN, pk);
#elif defined(OP_MLKEM_KEYGEN)
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
#elif defined(OP_MLKEM_ENCAPS)
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss_a, pk);
#elif defined(OP_MLKEM_DECAPS)
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss_b, ct, sk) != 0) {
        return 1;
    }
    return memcmp(ss_a, ss_b, SS_BYTES) == 0 ? 0 : 1;
#elif defined(OP_BASELINE)
    return randombytes(scratch, sizeof scratch);
#endif
}

int main(void)
{
    uart_puts("op=" OP_NAME "\n");
    uart_puts("fix=" FIX_NAME "\n");

    if (op_setup() != 0) {
        uart_puts("result=fail\n");
        uart_puts("stack_used_bytes=0\n");
        spike_finish(2);
    }

    uint32_t worst = 0;
    int bad = 0;
    for (int it = 0; it < ITERS; it++) {
        uintptr_t sp = read_sp();
        stack_paint_below(sp);
        int r = op_once(it);
        uint32_t used = stack_used_below(sp);
        if (used > worst) {
            worst = used;
        }
        if (r != 0) {
            bad = 1;
        }
    }

    uart_puts("result=");
    uart_puts(bad ? "fail" : "ok");
    uart_puts("\n");
    uart_puts("stack_used_bytes=");
    uart_putu(worst);
    uart_puts("\n");
    uart_puts("heap_used_bytes=");
    uart_putu(rt_heap_hwm());
    uart_puts("\n");

    spike_finish(bad ? 1 : 0);
    return 0;
}
