# Integrated RV32 boot image + attack harness.
#
#   make -C integration attacks   build every scenario, run under QEMU, assert
#   make -C integration images    just build the ELFs

HERE   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT   := $(HERE)..
SRC    := $(ROOT)/src
PQC    := $(ROOT)/third_party/pqclean
COMMON := $(PQC)/common
MLDSA_DIR := $(PQC)/crypto_sign/ml-dsa-44/clean
BUILD  := $(ROOT)/build/integration
OBJ    := $(BUILD)/obj

HOSTCC ?= cc
CROSS  := riscv64-unknown-elf-
RVCC   := $(CROSS)gcc
RVSIZE := $(CROSS)size
QEMU   ?= qemu-system-riscv32
PICOLIBC_INC := /usr/lib/picolibc/riscv64-unknown-elf/include

SCENARIOS := good rollback_replay tampered_counter cloned_flash

# --- host tool: gen_fixture ---
GEN_SRCS := $(HERE)gen_fixture.c \
            $(SRC)/puf/puf_sim.c $(SRC)/fuzzy/fuzzy_extractor.c $(SRC)/kdf/kdf.c \
            $(SRC)/rollback/rollback.c $(SRC)/secure_boot/secure_boot.c \
            $(SRC)/secure_boot/secure_boot_pack.c $(COMMON)/fips202.c \
            $(ROOT)/tests/common/detrand.c $(wildcard $(MLDSA_DIR)/*.c)
GEN_CFLAGS := -O2 -std=c11 -Wall -Wextra \
              -I$(HERE) -I$(SRC) -I$(COMMON) -I$(MLDSA_DIR)

$(BUILD)/gen_fixture: $(GEN_SRCS) | $(BUILD)
	$(HOSTCC) $(GEN_CFLAGS) $(GEN_SRCS) -o $@

# --- RV32 core objects (shared across scenarios) ---
RV_ARCH := -march=rv32imac_zicsr -mabi=ilp32
RV_CFLAGS := $(RV_ARCH) -Os -g -ffreestanding -nostdlib -fno-common \
             -ffunction-sections -fdata-sections -Wall -Wextra \
             -I$(HERE) -I$(SRC) -I$(COMMON) -I$(MLDSA_DIR) \
             -isystem $(PICOLIBC_INC)
RV_LDFLAGS := $(RV_ARCH) -nostdlib -static -Wl,--gc-sections \
              -Wl,--no-warn-rwx-segments -T $(HERE)rt/link.ld

RV_CSRC := $(HERE)boot.c $(HERE)fixture_access.c $(HERE)rt/rt.c \
           $(SRC)/puf/puf_sim.c $(SRC)/fuzzy/fuzzy_extractor.c $(SRC)/kdf/kdf.c \
           $(SRC)/rollback/rollback.c $(SRC)/secure_boot/secure_boot.c \
           $(COMMON)/fips202.c $(wildcard $(MLDSA_DIR)/*.c)
RV_OBJS := $(addprefix $(OBJ)/,$(notdir $(RV_CSRC:.c=.o)) start.o)

vpath %.c $(sort $(dir $(RV_CSRC)))
vpath %.S $(HERE)rt

$(OBJ)/%.o: %.c | $(OBJ)
	$(RVCC) $(RV_CFLAGS) -c $< -o $@
$(OBJ)/start.o: start.S | $(OBJ)
	$(RVCC) $(RV_CFLAGS) -c $< -o $@

$(BUILD) $(OBJ):
	mkdir -p $@

# --- per-scenario image ---
define IMAGE_RULE
$(BUILD)/$(1)/image.elf: $(BUILD)/gen_fixture $(RV_OBJS) $(HERE)rt/link.ld | $(BUILD)/$(1)
	$(BUILD)/gen_fixture $(1) > $(BUILD)/$(1)/fixture.c
	$(RVCC) $(RV_CFLAGS) -c $(BUILD)/$(1)/fixture.c -o $(BUILD)/$(1)/fixture.o
	$(RVCC) $(RV_CFLAGS) $(RV_OBJS) $(BUILD)/$(1)/fixture.o $(RV_LDFLAGS) -lgcc -o $$@
	@$(RVSIZE) $$@
$(BUILD)/$(1):
	mkdir -p $$@
endef
$(foreach s,$(SCENARIOS),$(eval $(call IMAGE_RULE,$(s))))

.PHONY: images attacks clean
images: $(foreach s,$(SCENARIOS),$(BUILD)/$(s)/image.elf)

attacks: images
	QEMU='$(QEMU)' SIZE='$(RVSIZE)' $(HERE)run-attacks.sh

clean:
	rm -rf $(BUILD)
