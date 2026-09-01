# Host tests: PQC primitives (official NIST KAT plus functional round-trip and
# negative tests) and the domain-separated KDF module.
#
# Targets:
#   make -C tests check            all of the below
#   make -C tests check-nistkat    ML-DSA-44 / ML-KEM-512 vs. NIST KAT hashes
#   make -C tests check-functest   round-trip + tamper-rejection
#   make -C tests check-kdf        KDF known answers + label independence

CC ?= cc

HERE   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT   := $(HERE)..
PQC    := $(ROOT)/third_party/pqclean
COMMON := $(PQC)/common
SRC    := $(ROOT)/src
BUILD  := $(ROOT)/build/tests

MLDSA_DIR := $(PQC)/crypto_sign/ml-dsa-44/clean
MLKEM_DIR := $(PQC)/crypto_kem/ml-kem-512/clean
MLDSA_NS  := PQCLEAN_MLDSA44_CLEAN
MLKEM_NS  := PQCLEAN_MLKEM512_CLEAN

# PQClean reference C and its test drivers: built with upstream's own flags.
PQC_CFLAGS := -O2 -std=c99 -Wall -Wextra -Wpedantic -Wvla -Werror -Wundef \
              -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
              -fstrict-aliasing -fno-common -I$(COMMON)

# Our own C: same rigor, C11.
OWN_CFLAGS := -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -Wshadow \
              -Wpointer-arith -Wcast-align -I$(SRC) -I$(COMMON)

NTESTS ?= 10

MLDSA_SRCS := $(wildcard $(MLDSA_DIR)/*.c)
MLKEM_SRCS := $(wildcard $(MLKEM_DIR)/*.c)
MLDSA_OBJS := $(patsubst $(MLDSA_DIR)/%.c,$(BUILD)/mldsa/%.o,$(MLDSA_SRCS))
MLKEM_OBJS := $(patsubst $(MLKEM_DIR)/%.c,$(BUILD)/mlkem/%.o,$(MLKEM_SRCS))

FIPS202_O := $(BUILD)/common/fips202.o
AES_O     := $(BUILD)/common/aes.o
RB_O      := $(BUILD)/common/randombytes.o
KATRNG_O  := $(BUILD)/common/nistkatrng.o
KDF_O     := $(BUILD)/kdf/kdf.o

BINS := $(BUILD)/nistkat_mldsa $(BUILD)/nistkat_mlkem \
        $(BUILD)/functest_mldsa $(BUILD)/functest_mlkem \
        $(BUILD)/shake256_kat $(BUILD)/test_kdf

.PHONY: all check check-nistkat check-functest check-shake check-kdf clean
all: $(BINS)

check: check-nistkat check-functest check-shake check-kdf

check-nistkat: $(BUILD)/nistkat_mldsa $(BUILD)/nistkat_mlkem
	@bash $(HERE)pqc/check-nistkat.sh $(BUILD)

check-functest: $(BUILD)/functest_mldsa $(BUILD)/functest_mlkem
	$(BUILD)/functest_mldsa  && echo "functest ml-dsa-44   PASS ($(NTESTS) iterations)"
	$(BUILD)/functest_mlkem  && echo "functest ml-kem-512  PASS ($(NTESTS) iterations)"

check-shake: $(BUILD)/shake256_kat
	$(BUILD)/shake256_kat

check-kdf: $(BUILD)/test_kdf
	$(BUILD)/test_kdf

$(BUILD)/common $(BUILD)/mldsa $(BUILD)/mlkem $(BUILD)/kdf:
	mkdir -p $@

# common objects
$(BUILD)/common/%.o: $(COMMON)/%.c | $(BUILD)/common
	$(CC) $(PQC_CFLAGS) -c $< -o $@
$(KATRNG_O): $(PQC)/test/common/nistkatrng.c | $(BUILD)/common
	$(CC) $(PQC_CFLAGS) -c $< -o $@

# scheme objects
$(BUILD)/mldsa/%.o: $(MLDSA_DIR)/%.c | $(BUILD)/mldsa
	$(CC) $(PQC_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(BUILD)/mlkem/%.o: $(MLKEM_DIR)/%.c | $(BUILD)/mlkem
	$(CC) $(PQC_CFLAGS) -I$(MLKEM_DIR) -c $< -o $@

# NIST KAT drivers (deterministic AES-256 CTR-DRBG; nistkatrng.c provides randombytes)
$(BUILD)/nistkat_mldsa: $(PQC)/test/crypto_sign/nistkat.c $(MLDSA_OBJS) $(FIPS202_O) $(AES_O) $(KATRNG_O) | $(BUILD)/common
	$(CC) $(PQC_CFLAGS) -I$(MLDSA_DIR) -DPQCLEAN_NAMESPACE=$(MLDSA_NS) $^ -o $@
$(BUILD)/nistkat_mlkem: $(PQC)/test/crypto_kem/nistkat.c $(MLKEM_OBJS) $(FIPS202_O) $(AES_O) $(KATRNG_O) | $(BUILD)/common
	$(CC) $(PQC_CFLAGS) -I$(MLKEM_DIR) -DPQCLEAN_NAMESPACE=$(MLKEM_NS) $^ -o $@

# functional tests (real OS RNG via randombytes.c)
$(BUILD)/functest_mldsa: $(PQC)/test/crypto_sign/functest.c $(MLDSA_OBJS) $(FIPS202_O) $(RB_O) | $(BUILD)/common
	$(CC) $(PQC_CFLAGS) -I$(MLDSA_DIR) -DPQCLEAN_NAMESPACE=$(MLDSA_NS) -DNTESTS=$(NTESTS) $^ -o $@
$(BUILD)/functest_mlkem: $(PQC)/test/crypto_kem/functest.c $(MLKEM_OBJS) $(FIPS202_O) $(RB_O) | $(BUILD)/common
	$(CC) $(PQC_CFLAGS) -I$(MLKEM_DIR) -DPQCLEAN_NAMESPACE=$(MLKEM_NS) -DNTESTS=$(NTESTS) $^ -o $@

# KDF module and the SHAKE256 KAT it rests on
$(KDF_O): $(SRC)/kdf/kdf.c $(SRC)/kdf/kdf.h | $(BUILD)/kdf
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/test_kdf: $(ROOT)/tests/kdf/test_kdf.c $(KDF_O) $(FIPS202_O) | $(BUILD)/kdf
	$(CC) $(OWN_CFLAGS) $^ -o $@
$(BUILD)/shake256_kat: $(ROOT)/tests/pqc/shake256_kat.c $(FIPS202_O) | $(BUILD)/kdf
	$(CC) $(OWN_CFLAGS) $^ -o $@

clean:
	rm -rf $(BUILD)
