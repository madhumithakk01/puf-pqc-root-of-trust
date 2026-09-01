# Build one footprint-spike image.
#
#   make OP=<op> OPT=<Os|O2> FIX=<runtime|static>
#
# op in: baseline, mldsa_keygen, mldsa_sign, mldsa_verify,
#        mlkem_keygen, mlkem_encaps, mlkem_decaps
#
# Output: build/spike/<OPT>/<FIX>/<OP>/{image.elf,image.map,*.su}
# measure.sh drives this across the whole matrix.

OP  ?= baseline
OPT ?= Os
FIX ?= runtime

SPIKE  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT   := $(SPIKE)../..
PQC    := $(ROOT)/third_party/pqclean
COMMON := $(PQC)/common
MLDSA_DIR := $(PQC)/crypto_sign/ml-dsa-44/clean
MLKEM_DIR := $(PQC)/crypto_kem/ml-kem-512/clean

OUT := $(ROOT)/build/spike/$(OPT)/$(FIX)/$(OP)

CROSS   := riscv64-unknown-elf-
CC      := $(CROSS)gcc
SIZE    := $(CROSS)size

ARCH := -march=rv32imac -mabi=ilp32

# picolibc headers only (string.h / stdlib.h for the PQClean sources); no libc
# is linked -- rt.c provides the handful of mem* functions.
PICOLIBC_INC := /usr/lib/picolibc/riscv64-unknown-elf/include

CFLAGS := $(ARCH) -$(OPT) -g -ffreestanding -nostdlib -fno-common \
          -ffunction-sections -fdata-sections -fstack-usage \
          -Wall -Wextra \
          -I$(SPIKE) -I$(SPIKE)rt -I$(COMMON) -isystem $(PICOLIBC_INC)

LDFLAGS := $(ARCH) -nostdlib -static -Wl,--gc-sections \
           -Wl,--no-warn-rwx-segments -Wl,-Map=$(OUT)/image.map \
           -T $(SPIKE)rt/link.ld

MLDSA_OPS := mldsa_keygen mldsa_sign mldsa_verify
MLKEM_OPS := mlkem_keygen mlkem_encaps mlkem_decaps

ifneq (,$(filter $(OP),$(MLDSA_OPS)))
  SCHEME_DIR := $(MLDSA_DIR)
else ifneq (,$(filter $(OP),$(MLKEM_OPS)))
  SCHEME_DIR := $(MLKEM_DIR)
else ifeq ($(OP),baseline)
  SCHEME_DIR :=
else
  $(error unknown OP '$(OP)')
endif

OP_UPPER := $(shell echo $(OP) | tr a-z A-Z)
CPPDEFS  := -DOP_$(OP_UPPER) -DOP_NAME='"$(OP)"'
ifeq ($(FIX),runtime)
  CPPDEFS += -DFIX_RUNTIME
endif
ifneq ($(SCHEME_DIR),)
  CFLAGS += -I$(SCHEME_DIR)
endif

SCHEME_SRCS := $(wildcard $(SCHEME_DIR)/*.c)
CSRCS := $(SPIKE)harness.c $(SPIKE)rt/rt.c $(COMMON)/fips202.c $(SCHEME_SRCS)
OBJS  := $(addprefix $(OUT)/,$(notdir $(CSRCS:.c=.o)) start.o)

vpath %.c $(sort $(dir $(CSRCS)))
vpath %.S $(SPIKE)rt

.PHONY: all
all: $(OUT)/image.elf

$(OUT):
	mkdir -p $(OUT)

$(OUT)/%.o: %.c | $(OUT)
	$(CC) $(CFLAGS) $(CPPDEFS) -c $< -o $@

$(OUT)/start.o: start.S | $(OUT)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/image.elf: $(OBJS) $(SPIKE)rt/link.ld | $(OUT)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -lgcc -o $@
	@$(SIZE) $@

.PHONY: clean
clean:
	rm -rf $(ROOT)/build/spike
