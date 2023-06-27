MICRO_ECC_MOD_DIR := $(USERMOD_DIR)

# Add all C files to SRC_USERMOD
SRC_USERMOD += $(MICRO_ECC_MOD_DIR)/micro_ecc.c

ifneq (,$(findstring -DMODULE_MICRO_ECC_ENABLED=1,$(CFLAGS_EXTRA)))
	SRC_USERMOD += $(MICRO_ECC_MOD_DIR)/micro-ecc/uECC.c
endif

CFLAGS_USERMOD += -I$(MICRO_ECC_MOD_DIR)/micro-ecc/
