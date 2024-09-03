# Makefile for Kernel-Level IDS with Security Enhancements

# Specify the kernel version
KERNEL_SRC := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Module Name
MODULE_NAME := ids_module

# Source Files
SRC_FILES := ids_module.c \
             buffer_overflow.c \
             rootkit_detection.c \
             unauthorized_access.c \
             ebpf_programs.c \
             pf_ring_module.c \
             kernel_integrity.c \
             syscall_filtering.c \
             privilege_escalation.c

# Object Files
OBJ_FILES := $(patsubst %.c,%.o,$(SRC_FILES))

# Compiler Flags
# -Werror: Treat warnings as errors
# -Wall -Wextra: Enable all warnings
# -Wpedantic: Enforce strict ISO C compliance
# -Wstack-protector: Warn about missing stack protector
# -fstack-protector-strong: Enable strong stack protection
# -fPIC: Generate position-independent code
# -fno-common: Disallow common symbols
# -fno-strict-aliasing: Disable strict aliasing optimizations
# -O2: Optimize code
EXTRA_CFLAGS := -Werror -Wall -Wextra -Wpedantic -Wstack-protector \
                -fstack-protector-strong -fPIC -fno-common -fno-strict-aliasing -O2

# Default Target
.PHONY: all
all: $(MODULE_NAME).ko

# Build Kernel Module
$(MODULE_NAME).ko: $(OBJ_FILES)
	@echo "Building kernel module..."
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

# Clean Build Artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
	@rm -f *.o *.mod.o *.mod.c *.symvers *.order

# Install Module
.PHONY: install
install: all
	@echo "Installing kernel module..."
	@sudo cp $(MODULE_NAME).ko /lib/modules/$(shell uname -r)/kernel/drivers/misc/
	@sudo depmod -a
	@sudo modprobe $(MODULE_NAME)
	@echo "Module installed and loaded successfully."

# Uninstall Module
.PHONY: uninstall
uninstall:
	@echo "Uninstalling kernel module..."
	@sudo modprobe -r $(MODULE_NAME)
	@sudo rm -f /lib/modules/$(shell uname -r)/kernel/drivers/misc/$(MODULE_NAME).ko
	@sudo depmod -a
	@echo "Module uninstalled successfully."

# Check Code Style with Checkpatch
.PHONY: check
check:
	@echo "Running code style checks..."
	@./scripts/checkpatch.pl --file --no-tree $(SRC_FILES)

# Static Code Analysis with Sparse
.PHONY: sparse
sparse:
	@echo "Running static code analysis with Sparse..."
	@sparse $(EXTRA_CFLAGS) $(SRC_FILES)

# Rebuild Module
.PHONY: rebuild
rebuild: clean all

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all        - Build the kernel module"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install and load the kernel module"
	@echo "  uninstall  - Unload and remove the kernel module"
	@echo "  check      - Run code style checks using checkpatch"
	@echo "  sparse     - Run static code analysis using Sparse"
	@echo "  rebuild    - Clean and rebuild the kernel module"
	@echo "  help       - Display this help message"
