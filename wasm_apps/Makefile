# Build WASM applications for Wendy MCU
#
# Requires: clang with wasm32 target (LLVM/clang 15+)
# Optional: wat2wasm (WABT), cargo (Rust), zig
#
# Usage:
#   make              # build C and WAT apps
#   make blink        # build just the C blink app
#   make wat_blink    # build just the WAT blink app
#   make rust_blink   # build the Rust blink app (requires cargo)
#   make zig_blink    # build the Zig blink app (requires zig)
#   make swift_display # build the Swift display app (requires Swift 6.0+)
#   make clean        # remove build artifacts

CC       ?= clang
CFLAGS    = --target=wasm32 -O2 -nostdlib -I include
LDFLAGS   = -Wl,--no-entry -Wl,--export=_start -Wl,--allow-undefined

C_APPS    = blink i2c_sensor
WAT_APPS  = wat_blink
OUTPUTS   = $(addsuffix .wasm, $(C_APPS) $(WAT_APPS))

.PHONY: all clean $(C_APPS) $(WAT_APPS) rust_blink zig_blink swift_display

all: $(OUTPUTS)

# --- C apps ---

blink: blink.wasm
i2c_sensor: i2c_sensor.wasm

blink.wasm: blink/blink.c include/wendy.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

i2c_sensor.wasm: i2c_sensor/i2c_sensor.c include/wendy.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# --- WAT app ---

wat_blink: wat_blink.wasm

wat_blink.wasm: wat_blink/blink.wat
	wat2wasm $< -o $@

# --- Rust app (requires rustup + cargo) ---

rust_blink:
	@command -v rustup >/dev/null 2>&1 || { echo "Error: rustup required (Homebrew Rust lacks cross-compile targets)." >&2; echo "Install via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2; exit 1; }
	rustup target add wasm32-unknown-unknown 2>/dev/null || true
	cd rust_blink && cargo build --release
	cp rust_blink/target/wasm32-unknown-unknown/release/rust_blink.wasm rust_blink.wasm

# --- Zig app (requires zig 0.13+) ---

zig_blink:
	cd zig_blink && zig build
	cp zig_blink/zig-out/bin/zig_blink.wasm zig_blink.wasm

# --- Swift display app (requires Swift 6.0+ with Embedded support) ---

swift_display:
	cd swift_display && swift build --triple wasm32-none-none-wasm
	cp swift_display/.build/debug/SwiftDisplay.wasm swift_display.wasm

clean:
	rm -f $(OUTPUTS) rust_blink.wasm zig_blink.wasm swift_display.wasm
	rm -rf rust_blink/target zig_blink/zig-out zig_blink/.zig-cache
	rm -rf swift_display/.build swift_blink/.build
