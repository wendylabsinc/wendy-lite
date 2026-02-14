# Build WASM applications for Wendy MCU
#
# Requires: clang with wasm32 target (LLVM/clang 15+)
#
# Usage:
#   make              # build all apps
#   make blink        # build just the blink app
#   make clean        # remove build artifacts

CC       ?= clang
CFLAGS    = --target=wasm32 -O2 -nostdlib -I include
LDFLAGS   = -Wl,--no-entry -Wl,--export=_start -Wl,--allow-undefined

APPS      = blink i2c_sensor
OUTPUTS   = $(addsuffix .wasm, $(APPS))

.PHONY: all clean $(APPS)

all: $(OUTPUTS)

blink: blink.wasm
i2c_sensor: i2c_sensor.wasm

blink.wasm: blink/blink.c include/wendy.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

i2c_sensor.wasm: i2c_sensor/i2c_sensor.c include/wendy.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(OUTPUTS)
