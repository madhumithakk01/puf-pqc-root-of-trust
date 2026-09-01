# Top-level build.
#
#   make            minimal RV32 image for the QEMU 'virt' machine
#   make run        boot it under QEMU
#   make boot-test  boot it and assert banner + clean exit
#   make test       host-side tests (PQC NIST KAT + functional, KDF)
#   make clean

CROSS   ?= riscv64-unknown-elf-
CC      := $(CROSS)gcc
SIZE    := $(CROSS)size
OBJDUMP := $(CROSS)objdump

# CC here is the RV32 cross compiler; the host test tree picks its own.
unexport CC

QEMU    ?= qemu-system-riscv32

PLATFORM := platform/qemu-virt-rv32
BUILD    := build
ELF      := $(BUILD)/hello.elf

ARCH_FLAGS := -march=rv32imac -mabi=ilp32

CFLAGS := $(ARCH_FLAGS) -Os -g3 -ffreestanding -nostdlib \
          -ffunction-sections -fdata-sections -fno-common \
          -Wall -Wextra -Werror

LDFLAGS := $(ARCH_FLAGS) -nostdlib -static \
           -Wl,--gc-sections -Wl,--build-id=none \
           -Wl,--no-warn-rwx-segments \
           -T $(PLATFORM)/link.ld

SRCS := $(PLATFORM)/start.S $(PLATFORM)/main.c

.PHONY: all
all: $(ELF)

$(ELF): $(SRCS) $(PLATFORM)/link.ld | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)
	$(SIZE) $@

$(BUILD):
	mkdir -p $(BUILD)

.PHONY: run
run: $(ELF)
	$(QEMU) -machine virt -nographic -bios none -kernel $(ELF) \
	        -no-reboot -semihosting-config enable=off

.PHONY: boot-test
boot-test: $(ELF)
	QEMU='$(QEMU)' tools/run-qemu.sh $(ELF)

.PHONY: disasm
disasm: $(ELF)
	$(OBJDUMP) -d $(ELF)

.PHONY: test
test:
	$(MAKE) -C tests check

.PHONY: clean
clean:
	rm -rf $(BUILD)
	$(MAKE) -C tests clean
