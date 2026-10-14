# Host tests: PQC primitives (official NIST KAT plus functional round-trip and
# negative tests) and the domain-separated KDF module.
#
# Targets:
#   make -C tests check            all of the below
#   make -C tests check-nistkat    ML-DSA-44 / ML-KEM-512 vs. NIST KAT hashes
#   make -C tests check-functest   round-trip + tamper-rejection
#   make -C tests check-shake      SHAKE256 known answers
#   make -C tests check-kdf        KDF known answers + label independence
#   make -C tests check-puf        simulated PUF: determinism + BER
#   make -C tests check-fuzzy      fuzzy extractor: KAT + success rate vs BER
#   make -C tests check-rollback   rollback counter: tamper + power-loss
#   make -C tests check-secure-boot secure boot decision matrix
#   make -C tests check-ota        confidential OTA: install/boot + wrong device
#   make -C tests check-attest     attestation: fresh report accepted, replay rejected
#   make -C tests check-ota-stream streaming AEAD equals one-shot; pack_signed round trip
#   make -C tests check-apm        APM1 app manifest: layout, round trip, refusals
#   make -C tests check-dlv            DLV1 delivery manifest: refusals and check order
#   make -C tests check-attest2        ATR2 report and RCP1 receipts: bytes, signatures, chain
#   make -C tests check-vn             von Neumann debias + fuzzy decoder statistics
#   make -C tests check-flashmap   pt.json matches rot_flash_map.h
#   make -C tests check-keys           RoT key hierarchy: ACVP vectors, determinism, RNG rules
#   make -C tests check-records        anchor, counter, journal, mailbox records incl. power-cut sweeps
#   make -C tests check-rot-boot       RoT boot state machine end to end (enroll, OTA, attacks, power cuts)
#   make -C tests check-rot-faults     RoT tamper cases and power-cut sweeps
#   make -C tests check-sensor         MAX30102 driver on a fake I2C bus
#   make -C tests check-dsp            pulse-oximeter DSP v1.0/v1.1/v1.2 on the golden trace
#   make -C tests check-selftest       health self-test judged by the RoT rule
#   make -C tests check-pqw1           PQW1 framing, resync, base64 line adapter
#   make -C tests check-appserver      application request handler (transfer, mailbox, receipts)
#   make -C tests check-forbid     never-do list (OTP writes, TBYB, restricted permissions)

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
KDF_O      := $(BUILD)/kdf/kdf.o
PUF_O      := $(BUILD)/puf/puf_sim.o
FUZZY_O    := $(BUILD)/fuzzy/fuzzy_extractor.o
ROLLBACK_O := $(BUILD)/rollback/rollback.o
SB_O       := $(BUILD)/secure_boot/secure_boot.o
SBPACK_O   := $(BUILD)/secure_boot/secure_boot_pack.o
DETRAND_O  := $(BUILD)/common/detrand.o
OTA_O      := $(BUILD)/ota/ota.o
OTA_AEAD_O := $(BUILD)/ota/ota_aead.o
OTA_PACK_O := $(BUILD)/ota/ota_pack.o
ATTEST_O   := $(BUILD)/attest/attest.o

PYTHON ?= python3

BINS := $(BUILD)/nistkat_mldsa $(BUILD)/nistkat_mlkem \
        $(BUILD)/functest_mldsa $(BUILD)/functest_mlkem \
        $(BUILD)/shake256_kat $(BUILD)/test_kdf $(BUILD)/test_puf_sim \
        $(BUILD)/test_fuzzy $(BUILD)/test_rollback $(BUILD)/test_secure_boot \
        $(BUILD)/test_ota $(BUILD)/test_attest $(BUILD)/attest_cli $(BUILD)/test_apm $(BUILD)/test_ota_stream $(BUILD)/test_dlv $(BUILD)/test_attest2 $(BUILD)/test_vn $(BUILD)/test_keys $(BUILD)/test_records $(BUILD)/test_rot_boot $(BUILD)/test_rot_faults $(BUILD)/test_sensor $(BUILD)/test_dsp $(BUILD)/test_selftest $(BUILD)/test_pqw1 $(BUILD)/test_appserver

.PHONY: all check check-nistkat check-functest check-shake check-kdf check-puf check-fuzzy check-rollback check-secure-boot check-ota check-attest check-forbid check-apm check-ota-stream check-dlv check-attest2 check-vn check-flashmap check-keys check-records check-rot-boot check-rot-faults check-sensor check-dsp check-selftest check-pqw1 check-appserver clean
all: $(BINS)

check: check-nistkat check-functest check-shake check-kdf check-puf check-fuzzy check-rollback check-secure-boot check-ota check-attest check-forbid check-apm check-ota-stream check-dlv check-attest2 check-vn check-flashmap check-keys check-records check-rot-boot check-rot-faults check-sensor check-dsp check-selftest check-pqw1 check-appserver

check-nistkat: $(BUILD)/nistkat_mldsa $(BUILD)/nistkat_mlkem
	@bash $(HERE)pqc/check-nistkat.sh $(BUILD)

check-functest: $(BUILD)/functest_mldsa $(BUILD)/functest_mlkem
	$(BUILD)/functest_mldsa  && echo "functest ml-dsa-44   PASS ($(NTESTS) iterations)"
	$(BUILD)/functest_mlkem  && echo "functest ml-kem-512  PASS ($(NTESTS) iterations)"

check-shake: $(BUILD)/shake256_kat
	$(BUILD)/shake256_kat

check-kdf: $(BUILD)/test_kdf
	$(BUILD)/test_kdf

check-puf: $(BUILD)/test_puf_sim
	$(BUILD)/test_puf_sim

check-fuzzy: $(BUILD)/test_fuzzy
	$(BUILD)/test_fuzzy

check-rollback: $(BUILD)/test_rollback
	$(BUILD)/test_rollback

check-secure-boot: $(BUILD)/test_secure_boot
	$(BUILD)/test_secure_boot

check-ota: $(BUILD)/test_ota
	$(BUILD)/test_ota

check-attest: $(BUILD)/test_attest $(BUILD)/attest_cli
	$(BUILD)/test_attest
	$(PYTHON) $(ROOT)/server/attest/test_attest_server.py $(BUILD)/attest_cli

check-ota-stream: $(BUILD)/test_ota_stream
	$(BUILD)/test_ota_stream

check-apm: $(BUILD)/test_apm
	$(BUILD)/test_apm

check-dlv: $(BUILD)/test_dlv
	$(BUILD)/test_dlv

check-attest2: $(BUILD)/test_attest2 $(BUILD)/attest_cli
	$(BUILD)/test_attest2
	$(PYTHON) $(ROOT)/server/attest/test_attest2_server.py $(BUILD)/attest_cli

check-vn: $(BUILD)/test_vn
	$(BUILD)/test_vn

check-flashmap:
	$(PYTHON) $(ROOT)/tools/ci/check_flash_map.py

check-keys: $(BUILD)/test_keys
	$(BUILD)/test_keys

check-records: $(BUILD)/test_records
	$(BUILD)/test_records

check-rot-boot: $(BUILD)/test_rot_boot
	$(BUILD)/test_rot_boot

check-rot-faults: $(BUILD)/test_rot_faults
	$(BUILD)/test_rot_faults

check-sensor: $(BUILD)/test_sensor
	$(BUILD)/test_sensor

check-dsp: $(BUILD)/test_dsp
	$(BUILD)/test_dsp

check-selftest: $(BUILD)/test_selftest
	$(BUILD)/test_selftest

check-pqw1: $(BUILD)/test_pqw1
	$(BUILD)/test_pqw1

check-appserver: $(BUILD)/test_appserver
	$(BUILD)/test_appserver

check-forbid:
	bash $(ROOT)/tools/ci/forbid.sh

$(BUILD)/common $(BUILD)/mldsa $(BUILD)/mlkem $(BUILD)/kdf $(BUILD)/puf $(BUILD)/fuzzy $(BUILD)/rollback $(BUILD)/secure_boot $(BUILD)/ota $(BUILD)/attest:
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

# simulated PUF
$(PUF_O): $(SRC)/puf/puf_sim.c $(SRC)/puf/puf_sim.h | $(BUILD)/puf
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/test_puf_sim: $(ROOT)/tests/puf/test_puf_sim.c $(PUF_O) $(FIPS202_O) | $(BUILD)/puf
	$(CC) $(OWN_CFLAGS) $^ -o $@

# fuzzy extractor
$(FUZZY_O): $(SRC)/fuzzy/fuzzy_extractor.c $(SRC)/fuzzy/fuzzy_extractor.h | $(BUILD)/fuzzy
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/test_fuzzy: $(ROOT)/tests/fuzzy/test_fuzzy.c $(FUZZY_O) $(PUF_O) $(FIPS202_O) | $(BUILD)/fuzzy
	$(CC) $(OWN_CFLAGS) $^ -o $@

# rollback counter
$(ROLLBACK_O): $(SRC)/rollback/rollback.c $(SRC)/rollback/rollback.h | $(BUILD)/rollback
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/test_rollback: $(ROOT)/tests/rollback/test_rollback.c $(ROLLBACK_O) $(KDF_O) $(PUF_O) $(FUZZY_O) $(FIPS202_O) | $(BUILD)/rollback
	$(CC) $(OWN_CFLAGS) $^ -o $@

# secure boot (needs ML-DSA api.h + a deterministic randombytes)
$(DETRAND_O): $(ROOT)/tests/common/detrand.c | $(BUILD)/common
	$(CC) $(PQC_CFLAGS) -c $< -o $@
$(SB_O): $(SRC)/secure_boot/secure_boot.c $(SRC)/secure_boot/secure_boot.h | $(BUILD)/secure_boot
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(SBPACK_O): $(SRC)/secure_boot/secure_boot_pack.c $(SRC)/secure_boot/secure_boot.h | $(BUILD)/secure_boot
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(BUILD)/test_secure_boot: $(ROOT)/tests/secure_boot/test_secure_boot.c \
        $(SB_O) $(SBPACK_O) $(ROLLBACK_O) $(KDF_O) $(MLDSA_OBJS) $(FIPS202_O) $(DETRAND_O) | $(BUILD)/secure_boot
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) $^ -o $@

# confidential OTA
$(OTA_AEAD_O): $(SRC)/ota/ota_aead.c $(SRC)/ota/ota_aead.h | $(BUILD)/ota
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(OTA_O): $(SRC)/ota/ota.c $(SRC)/ota/ota.h $(SRC)/ota/ota_aead.h | $(BUILD)/ota
	$(CC) $(OWN_CFLAGS) -I$(MLKEM_DIR) -c $< -o $@
$(OTA_PACK_O): $(SRC)/ota/ota_pack.c $(SRC)/ota/ota.h $(SRC)/ota/ota_aead.h | $(BUILD)/ota
	$(CC) $(OWN_CFLAGS) -I$(MLKEM_DIR) -c $< -o $@
$(BUILD)/test_ota: $(ROOT)/tests/ota/test_ota.c \
        $(OTA_O) $(OTA_AEAD_O) $(OTA_PACK_O) $(SB_O) $(SBPACK_O) $(ROLLBACK_O) $(KDF_O) \
        $(MLKEM_OBJS) $(MLDSA_OBJS) $(FIPS202_O) $(DETRAND_O) | $(BUILD)/ota
	$(CC) $(OWN_CFLAGS) $^ -o $@

$(BUILD)/test_ota_stream: $(ROOT)/tests/ota/test_ota_stream.c         $(OTA_AEAD_O) $(OTA_PACK_O) $(SB_O) $(SBPACK_O) $(ROLLBACK_O) $(KDF_O)         $(MLKEM_OBJS) $(MLDSA_OBJS) $(FIPS202_O) $(DETRAND_O) | $(BUILD)/ota
	$(CC) $(OWN_CFLAGS) $^ -o $@

# attestation: device-side lib + a thin ML-DSA CLI the Python server calls
$(ATTEST_O): $(SRC)/attest/attest.c $(SRC)/attest/attest.h | $(BUILD)/attest
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(BUILD)/test_attest: $(ROOT)/tests/attest/test_attest.c \
        $(ATTEST_O) $(MLDSA_OBJS) $(FIPS202_O) $(DETRAND_O) | $(BUILD)/attest
	$(CC) $(OWN_CFLAGS) $^ -o $@
$(BUILD)/attest_cli: $(ROOT)/tools/attest/attest_cli.c \
        $(MLDSA_OBJS) $(FIPS202_O) | $(BUILD)/attest
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) $^ -o $@

$(BUILD)/dlv:
	mkdir -p $@
$(BUILD)/dlv/dlv.o: $(SRC)/dlv/dlv.c $(SRC)/dlv/dlv.h | $(BUILD)/dlv
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(BUILD)/test_dlv: $(ROOT)/tests/dlv/test_dlv.c $(BUILD)/dlv/dlv.o \
        $(MLDSA_OBJS) $(FIPS202_O) $(DETRAND_O) | $(BUILD)/dlv
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) $^ -o $@

$(BUILD)/rot:
	mkdir -p $@
$(BUILD)/attest/attest2.o: $(SRC)/attest/attest2.c $(SRC)/attest/attest2.h | $(BUILD)/attest
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(BUILD)/rot/rot_receipt.o: $(SRC)/rot/rot_receipt.c $(SRC)/rot/rot_receipt.h | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(BUILD)/test_attest2: $(ROOT)/tests/attest/test_attest2.c $(BUILD)/attest/attest2.o \
        $(BUILD)/rot/rot_receipt.o $(MLDSA_OBJS) $(FIPS202_O) $(DETRAND_O) | $(BUILD)/attest
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) $^ -o $@

$(BUILD)/puf/vn_debias.o: $(SRC)/puf/vn_debias.c $(SRC)/puf/vn_debias.h | $(BUILD)/puf
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/test_vn: $(ROOT)/tests/puf/test_vn.c $(BUILD)/puf/vn_debias.o $(PUF_O) $(FUZZY_O) \
        $(FIPS202_O) | $(BUILD)/puf
	$(CC) $(OWN_CFLAGS) $^ -o $@

ROTO := $(BUILD)/rot
$(BUILD)/rot/rot_rng.o: $(SRC)/rot/rot_rng.c $(SRC)/rot/rot_rng.h $(SRC)/rot/rot_util.h | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/rot/rot_keys.o: $(SRC)/rot/rot_keys.c $(SRC)/rot/rot_keys.h $(SRC)/rot/rot_util.h | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/test_keys: $(ROOT)/tests/rot/test_keys.c $(BUILD)/rot/rot_keys.o $(BUILD)/rot/rot_rng.o \
        $(KDF_O) $(MLDSA_OBJS) $(MLKEM_OBJS) $(FIPS202_O) | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) $^ -o $@

ROTLIB := $(BUILD)/rot/rot_flash.o $(BUILD)/rot/rot_anchor.o $(BUILD)/rot/rot_counter.o \
          $(BUILD)/rot/rot_journal.o $(BUILD)/rot/rot_mailbox.o $(BUILD)/rot/rot_mailbox_build.o $(BUILD)/rot/rot_crc32.o
ROTCORE := $(ROTLIB) $(BUILD)/rot/rot_helper.o $(BUILD)/rot/rot_enroll.o $(BUILD)/rot/rot_keys.o \
           $(BUILD)/rot/rot_rng.o $(BUILD)/rot/rot_receipt.o $(BUILD)/rot/rot_receipts.o \
           $(BUILD)/rot/rot_slot.o $(BUILD)/rot/rot_hev.o $(BUILD)/rot/rot_trial.o $(BUILD)/rot/rot_install.o \
           $(BUILD)/rot/rot_handoff.o $(BUILD)/rot/rot_boot.o \
           $(BUILD)/attest/attest2.o $(BUILD)/dlv/dlv.o $(BUILD)/apm/apm.o \
           $(BUILD)/puf/vn_debias.o $(FUZZY_O) $(PUF_O) \
           $(OTA_O) $(OTA_AEAD_O) $(OTA_PACK_O) $(SB_O) $(SBPACK_O) $(ROLLBACK_O) $(KDF_O) \
           $(MLDSA_OBJS) $(MLKEM_OBJS) $(FIPS202_O)
$(BUILD)/apm/apm.o: $(SRC)/apm/apm.c $(SRC)/apm/apm.h | $(BUILD)/apm
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/rot/%.o: $(SRC)/rot/%.c $(wildcard $(SRC)/rot/*.h) | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) -I$(MLDSA_DIR) -c $< -o $@
$(BUILD)/softdev:
	mkdir -p $@
$(BUILD)/softdev/flash_model.o: $(ROOT)/host/softdev/flash_model.c $(ROOT)/host/softdev/flash_model.h | $(BUILD)/softdev
	$(CC) $(OWN_CFLAGS) -c $< -o $@
$(BUILD)/test_records: $(ROOT)/tests/rot/test_records.c $(ROTLIB) $(BUILD)/softdev/flash_model.o \
        $(ROLLBACK_O) $(KDF_O) $(FIPS202_O) | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) -I$(ROOT)/host/softdev $^ -o $@

$(BUILD)/test_rot_boot: $(ROOT)/tests/rot/test_rot_boot.c $(ROOT)/tests/rot/rot_fixture.c $(ROOT)/tests/rot/rot_fixture.h \
        $(ROTCORE) $(BUILD)/softdev/flash_model.o | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) -I$(ROOT)/host/softdev -I$(ROOT)/tests/rot $(ROOT)/tests/rot/test_rot_boot.c \
	    $(ROOT)/tests/rot/rot_fixture.c $(ROTCORE) $(BUILD)/softdev/flash_model.o -lm -o $@

$(BUILD)/test_rot_faults: $(ROOT)/tests/rot/test_rot_faults.c $(ROOT)/tests/rot/rot_fixture.c $(ROOT)/tests/rot/rot_fixture.h \
        $(ROTCORE) $(BUILD)/softdev/flash_model.o | $(BUILD)/rot
	$(CC) $(OWN_CFLAGS) -I$(ROOT)/host/softdev -I$(ROOT)/tests/rot $(ROOT)/tests/rot/test_rot_faults.c \
	    $(ROOT)/tests/rot/rot_fixture.c $(ROTCORE) $(BUILD)/softdev/flash_model.o -lm -o $@

APPDIR := $(ROOT)/app
$(BUILD)/app:
	mkdir -p $@
$(BUILD)/test_sensor: $(ROOT)/tests/app/test_sensor.c $(APPDIR)/sensor/max30102.c $(APPDIR)/sensor/max30102.h | $(BUILD)/app
	$(CC) $(OWN_CFLAGS) -I$(APPDIR) -I$(ROOT)/tests/app $(ROOT)/tests/app/test_sensor.c $(APPDIR)/sensor/max30102.c -o $@

$(BUILD)/test_dsp: $(ROOT)/tests/app/test_dsp.c $(APPDIR)/dsp/dsp.c $(APPDIR)/dsp/dsp.h \
        $(APPDIR)/golden/golden_trace.c $(APPDIR)/golden/golden_trace.h | $(BUILD)/app
	$(CC) $(OWN_CFLAGS) -I$(APPDIR) $(ROOT)/tests/app/test_dsp.c $(APPDIR)/dsp/dsp.c \
	    $(APPDIR)/golden/golden_trace.c -lm -o $@

$(BUILD)/test_selftest: $(ROOT)/tests/app/test_selftest.c $(ROOT)/tests/app/fake_i2c.h \
        $(APPDIR)/health/selftest.c $(APPDIR)/health/selftest.h $(APPDIR)/dsp/dsp.c \
        $(APPDIR)/sensor/max30102.c $(APPDIR)/golden/golden_trace.c $(ROTCORE) | $(BUILD)/app
	$(CC) $(OWN_CFLAGS) -I$(APPDIR) -I$(ROOT)/tests/app $(ROOT)/tests/app/test_selftest.c \
	    $(APPDIR)/health/selftest.c $(APPDIR)/dsp/dsp.c $(APPDIR)/sensor/max30102.c \
	    $(APPDIR)/golden/golden_trace.c $(ROTCORE) -lm -o $@

$(BUILD)/test_pqw1: $(ROOT)/tests/app/test_pqw1.c $(APPDIR)/proto/pqw1.c $(APPDIR)/proto/pqw1.h \
        $(SRC)/rot/rot_crc32.c | $(BUILD)/app
	$(CC) $(OWN_CFLAGS) -I$(APPDIR) $(ROOT)/tests/app/test_pqw1.c $(APPDIR)/proto/pqw1.c $(SRC)/rot/rot_crc32.c -o $@

$(BUILD)/test_appserver: $(ROOT)/tests/app/test_appserver.c $(APPDIR)/proto/app_server.c $(APPDIR)/proto/app_server.h \
        $(APPDIR)/proto/pqw1.c $(SRC)/rot/rot_crc32.c $(SRC)/rot/rot_mailbox_build.c $(SRC)/rot/rot_handoff.c | $(BUILD)/app
	$(CC) $(OWN_CFLAGS) -I$(APPDIR) $(ROOT)/tests/app/test_appserver.c $(APPDIR)/proto/app_server.c \
	    $(APPDIR)/proto/pqw1.c $(SRC)/rot/rot_crc32.c $(SRC)/rot/rot_mailbox_build.c $(SRC)/rot/rot_handoff.c -o $@

clean:
	rm -rf $(BUILD)

$(BUILD)/apm:
	mkdir -p $@

$(BUILD)/test_apm: $(ROOT)/tests/apm/test_apm.c $(SRC)/apm/apm.c $(SRC)/apm/apm.h | $(BUILD)/apm
	$(CC) $(OWN_CFLAGS) $(ROOT)/tests/apm/test_apm.c $(SRC)/apm/apm.c -o $@
