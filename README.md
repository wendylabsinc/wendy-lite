# Wendy Lite

Wendy Lite is a WebAssembly runtime for ESP32 microcontrollers. Write your application in **Swift**, **Rust**, **C/C++**, **AssemblyScript**, or **WAT**, compile it to `.wasm`, and run it on real hardware.

The Wendy host firmware exposes a comprehensive set of hardware APIs through WASM imports — GPIO, I2C, SPI, UART, RMT, NeoPixel, BLE, WiFi, sockets, TLS, USB, NVS storage, timers, and OpenTelemetry.

## Writing WASM Apps

Every Wendy app is a `.wasm` binary that exports a `_start()` function. The firmware loads it into the WAMR runtime and calls `_start`. Your app talks to hardware through host-imported functions from the `"wendy"` module.

Pick your language below.

### Swift

Wendy Lite ships a **WendyLite** SwiftPM library. Add it as a dependency and `import WendyLite`.

**Requirements:** Swift 6.0+ with Embedded Swift support (install via [swiftly](https://swiftlang.github.io/swiftly/))

**1. Create your app package:**

```
mkdir MyApp && cd MyApp
```

```swift
// Package.swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/AnyWendy/wendy-lite.git", branch: "main"),
    ],
    targets: [
        .executableTarget(
            name: "MyApp",
            dependencies: [
                .product(name: "WendyLite", package: "wendy-lite"),
            ],
            swiftSettings: [
                .enableExperimentalFeature("Embedded"),
                .unsafeFlags(["-wmo"]),
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-Xclang-linker", "-nostdlib",
                    "-Xlinker", "--no-entry",
                    "-Xlinker", "--export=_start",
                    "-Xlinker", "--allow-undefined",
                    "-Xlinker", "--initial-memory=131072",
                    "-Xlinker", "-z", "-Xlinker", "stack-size=8192",
                ])
            ]
        )
    ]
)
```

**2. Write your app:**

```swift
// Sources/MyApp/main.swift
import WendyLite

@_cdecl("_start")
func start() {
    GPIO.configure(pin: 8, mode: .output)

    while true {
        GPIO.write(pin: 8, level: 1)
        System.sleepMs(500)
        GPIO.write(pin: 8, level: 0)
        System.sleepMs(500)
    }
}
```

**3. Build:**

```bash
swift build --triple wasm32-unknown-none-wasm -c release
```

The `WendyLite` module provides Swift-idiomatic APIs for every subsystem:

| Namespace | Functions |
|-----------|-----------|
| `GPIO` | `configure`, `read`, `write`, `setPWM`, `analogRead`, `setInterrupt`, `clearInterrupt` |
| `I2C` | `initialize`, `scan`, `read`, `write`, `writeRead` |
| `SPI` | `open`, `close`, `transfer` |
| `UART` | `open`, `close`, `read`, `write`, `available`, `flush`, `setOnReceive` |
| `RMT` | `configure`, `transmit`, `release` |
| `NeoPixel` | `initialize`, `set`, `clear` |
| `Timer` | `delayMs`, `millis`, `setTimeout`, `setInterval`, `cancel` |
| `System` | `uptimeMs`, `reboot`, `firmwareVersion`, `deviceId`, `sleepMs`, `yield` |
| `Console` | `print` |
| `Storage` | `get`, `set`, `delete`, `exists` |
| `BLE` | `initialize`, `startAdvertising`, `stopAdvertising`, `startScan`, `stopScan`, `connect`, `disconnect` |
| `GATTS` | `addService`, `addCharacteristic`, `setValue`, `notify`, `onWrite` |
| `GATTC` | `discover`, `read`, `write` |
| `WiFi` | `connect`, `disconnect`, `status`, `getIP`, `rssi`, `startAP`, `stopAP` |
| `Net` | `socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`, `close` |
| `DNS` | `resolve` |
| `TLS` | `connect`, `send`, `recv`, `close` |
| `OTel` | `log`, `counterAdd`, `gaugeSet`, `histogramRecord`, `spanStart`, `spanSetAttribute`, `spanSetStatus`, `spanEnd` |
| `USB` | `cdcWrite`, `cdcRead`, `hidSendReport` |

Type-safe enums: `GPIOMode`, `GPIOPull`, `GPIOInterruptEdge`, `SocketDomain`, `SocketType`, `OTelLogLevel`.

The raw C functions are also available through the re-exported `CWendyLite` module.

---

### Rust

Wendy Lite ships a **wendy-lite** Rust crate (`#![no_std]`). Add it as a dependency and use the safe wrapper modules.

**Requirements:** Rust toolchain with `wasm32-unknown-unknown` target

```bash
rustup target add wasm32-unknown-unknown
```

**1. Create your app:**

```bash
cargo init --lib my_app && cd my_app
```

**2. Configure `Cargo.toml`:**

```toml
[package]
name = "my_app"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wendy-lite = { git = "https://github.com/AnyWendy/wendy-lite.git" }

[profile.release]
opt-level = "z"
lto = true
strip = true
panic = "abort"
```

**3. Add `.cargo/config.toml`:**

```toml
[build]
target = "wasm32-unknown-unknown"

[target.wasm32-unknown-unknown]
rustflags = ["-C", "link-args=--allow-undefined --initial-memory=131072 -z stack-size=8192"]
```

**4. Write your app:**

```rust
// src/lib.rs
#![no_std]

use wendy_lite::{gpio, sys};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
pub extern "C" fn _start() {
    gpio::configure(8, gpio::Mode::Output, gpio::Pull::None);

    loop {
        gpio::write(8, 1);
        sys::sleep_ms(500);
        gpio::write(8, 0);
        sys::sleep_ms(500);
    }
}
```

**5. Build:**

```bash
cargo build --release
# Output: target/wasm32-unknown-unknown/release/my_app.wasm
```

Available modules: `gpio`, `i2c`, `spi`, `uart`, `rmt`, `neopixel`, `timer`, `sys`, `console`, `storage`, `ble` (with `ble::gatts`, `ble::gattc`), `wifi`, `net`, `dns`, `tls`, `otel`, `usb`.

The Rust API uses slices where possible — `i2c::write(bus, addr, &data)` instead of raw pointer + length.

---

### C / C++

Include the `wendy.h` header. It declares all host-imported functions with the correct WASM import attributes.

**Requirements:** clang with `wasm32` target (LLVM/clang 15+)

**1. Write your app:**

```c
// blink.c
#include "wendy.h"

void _start(void) {
    gpio_configure(8, WENDY_GPIO_OUTPUT, WENDY_GPIO_PULL_NONE);

    for (;;) {
        gpio_write(8, 1);
        timer_delay_ms(500);
        gpio_write(8, 0);
        timer_delay_ms(500);
    }
}
```

**2. Build:**

```bash
clang --target=wasm32 -O2 -nostdlib \
    -I path/to/wendy-lite/wasm_apps/include \
    -Wl,--no-entry -Wl,--export=_start -Wl,--allow-undefined \
    -o blink.wasm blink.c
```

The header is at `wasm_apps/include/wendy.h`. Constants use the `WENDY_` prefix (e.g., `WENDY_GPIO_OUTPUT`, `WENDY_AF_INET`, `WENDY_OTEL_INFO`).

---

### AssemblyScript

Declare the host functions with `@external("wendy", "...")` and export `_start`.

```typescript
// assembly/index.ts
@external("wendy", "gpio_configure")
declare function gpio_configure(pin: i32, mode: i32, pull: i32): i32;

@external("wendy", "gpio_write")
declare function gpio_write(pin: i32, level: i32): i32;

@external("wendy", "sys_sleep_ms")
declare function sys_sleep_ms(ms: i32): void;

export function _start(): void {
    gpio_configure(8, 1, 0);
    while (true) {
        gpio_write(8, 1);
        sys_sleep_ms(500);
        gpio_write(8, 0);
        sys_sleep_ms(500);
    }
}
```

Build with `npm run build` (requires `assemblyscript`).

---

## Deploying to Device

Once you have a `.wasm` binary, convert it to a C header and rebuild the firmware:

```bash
# Convert and rebuild (Swift example)
./wasm_apps/build.sh swift_blink

# Or manually:
./wasm_apps/wasm2header.sh my_app.wasm main/demo_wasm.h
idf.py build
idf.py flash
```

## Async Callbacks

Some APIs accept a `handler_id` parameter for async events (GPIO interrupts, timers, BLE events). To receive these callbacks, export a handler function:

```c
// C
void wendy_handle_callback(int handler_id, int arg0, int arg1, int arg2) {
    // Dispatched when you call sys_yield()
}
```

```swift
// Swift
@_cdecl("wendy_handle_callback")
func handleCallback(_ handlerId: Int32, _ arg0: Int32, _ arg1: Int32, _ arg2: Int32) {
    // Dispatched when you call System.yield()
}
```

```rust
// Rust
#[no_mangle]
pub extern "C" fn wendy_handle_callback(handler_id: i32, arg0: i32, arg1: i32, arg2: i32) {
    // Dispatched when you call sys::yield_now()
}
```

Callbacks are dispatched when your app calls `sys_yield()` / `System.yield()` / `sys::yield_now()`.

## API Reference

The full list of host functions is defined in [`wasm_apps/include/wendy.h`](wasm_apps/include/wendy.h). It covers:

- **GPIO** — digital I/O, PWM, analog read, interrupts
- **I2C** — bus init, scan, read, write, write-then-read
- **SPI** — open, close, bidirectional transfer
- **UART** — open, close, read, write, flush, receive callbacks
- **RMT** — timing-buffer transmit (for LED protocols, IR, etc.)
- **NeoPixel** — WS2812 high-level API
- **Timer** — delay, millis, timeout, interval
- **System** — uptime, reboot, sleep, yield, firmware version, device ID
- **Console** — print output
- **Storage** — NVS key-value get/set/delete/exists
- **BLE** — advertising, scanning, connect, GATT server + client
- **WiFi** — station connect/disconnect, AP mode, RSSI
- **Sockets** — TCP/UDP socket, connect, bind, listen, accept, send, recv
- **DNS** — hostname resolution
- **TLS** — encrypted connect, send, recv
- **OpenTelemetry** — structured logging, counters, gauges, histograms, tracing spans
- **USB** — CDC read/write, HID reports
