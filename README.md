# Wendy Lite

Wendy Lite is a WebAssembly runtime for ESP32 microcontrollers. Write your application in **Swift**, **Rust**, **C/C++**, **AssemblyScript**, or **WAT**, compile it to `.wasm`, and run it on real hardware.

The Wendy host firmware exposes a comprehensive set of hardware APIs through WASM imports — GPIO, I2C, SPI, UART, RMT, NeoPixel, BLE, WiFi, sockets, TLS, USB, NVS storage, timers, and OpenTelemetry.

Wendy Lite also supports native applications, written in C and C++ and built using the ESP-IDF tools and API.

## Supported Hardware

Wendy Lite firmware builds for five ESP-IDF targets:

| Target | Reference board (Espressif dev kit) | Wi-Fi / BT |
|---|---|---|
| `esp32c5` | Espressif ESP32-C5-DevKitC | Native (2.4 / 5 GHz Wi-Fi 6 + BLE) |
| `esp32c6` | Espressif ESP32-C6-DevKitC | Native Wi-Fi 6 + BLE |
| `esp32c61` | Espressif ESP32-C61-DevKitC | Native Wi-Fi 6 + BLE — no WASM app support yet, see [ESP32-C61 notes](#esp32-c61-notes) |
| `esp32p4` | None (see [ESP32-P4 notes](#esp32-p4-notes)) | Via on-board ESP32-C6 over SDIO (ESP-Hosted) |
| `esp32s3` | None | Native Wi-Fi + BLE |

Each target except `esp32p4` has a **generic board** configuration (`boards/<target>_generic*.cfg`) that runs on the reference board above unmodified, using 4 MB flash, no PSRAM, and the system allocator for the WAMR pool. `esp32p4` has no generic board at all — a board-specific overlay is mandatory (see [ESP32-P4 notes](#esp32-p4-notes)).

Beyond the generic boards, Wendy Lite has overlays for the following boards (from `catalog.json`), each with its own flash size, PSRAM, and peripherals:

| Board | Target | Flash | PSRAM | Notes |
|---|---|---|---|---|
| Waveshare ESP32-P4-WIFI6-Touch-LCD-4B | `esp32p4` | 32 MB | 32 MB | Wi-Fi/BT via on-board ESP32-C6 (SDIO/ESP-Hosted); 4″ 720×720 MIPI-DSI touch panel; WAMR pool: 24 MiB from PSRAM |
| DFRobot FireBeetle 2 ESP32-P4 (DFR1172) | `esp32p4` | 16 MB | 32 MB | Wi-Fi/BT via on-board ESP32-C6 (SDIO/ESP-Hosted); headless; WAMR pool: 24 MiB from PSRAM |
| Seeed Studio XIAO ESP32S3 | `esp32s3` | 8 MB | 8 MB | Native Wi-Fi/BT; native app support (OTA partition layout); WAMR pool: system allocator |
| M5Stack StampS3 | `esp32s3` | 8 MB | – | Native Wi-Fi/BT; native app support (OTA partition layout); WAMR pool: system allocator |

The targets share the same source tree. Per-target overrides live in `sdkconfig.defaults.<target>`. Running `idf.py set-target <target>` on its own selects that target's reference board; to select a specific board instead, pass its overlay argfile from `boards/` before `set-target` (e.g. `idf.py @boards/<board_cfg>.cfg set-target <target>`. See [ESP32-P4 notes](#esp32-p4-notes) below for `esp32p4`, which has no bare-target option).

Guest WASM binaries are interchangeable between targets that support WASM apps.

## Building the Firmware

### Pick a target and a board

For a generic board or the reference dev kit, just set the target:

```bash
idf.py set-target esp32c5   # Espressif ESP32-C5-DevKitC
idf.py set-target esp32c6   # Espressif ESP32-C6-DevKitC
idf.py set-target esp32c61  # Espressif ESP32-C61-DevKitC
idf.py set-target esp32s3   # generic ESP32-S3 board
```

For a specific board, select its overlay from `boards/` before `set-target`:

```bash
idf.py @boards/waveshare_lcd_4b.cfg          set-target esp32p4  # Waveshare ESP32-P4-WIFI6-Touch-LCD-4B (32 MB flash)
idf.py @boards/dfr1172_firebeetle.cfg        set-target esp32p4  # DFRobot FireBeetle 2 ESP32-P4 (DFR1172) (16 MB flash)
idf.py @boards/seeed_xiao_esp32s3_native.cfg set-target esp32s3  # Seeed Studio XIAO ESP32S3 (8 MB flash, OTA app slots)
idf.py @boards/m5_stamp_s3_native.cfg        set-target esp32s3  # M5Stack StampS3 (8 MB flash, no PSRAM, OTA app slots)
```

### Build, flash, monitor

```bash
idf.py build
idf.py flash
idf.py monitor
```

### ESP32-C61 notes

No published `espressif/wasm-micro-runtime` release lists `esp32c61` as a supported target yet, so WASM app support -- and every component that exists solely to bridge native code to WASM guests (`wendy_wasm`, `wendy_hal`, `wendy_hal_export`, and everything `wendy_hal_export` pulls in) -- is dropped from the build on this target via `EXCLUDE_COMPONENTS` set conditionally on `IDF_TARGET` in the root `CMakeLists.txt`, rather than depending on an unofficial WAMR fork. This is target-conditioned in `CMakeLists.txt` itself (not the board argfile) so it applies however `esp32c61` gets selected as the target. The C61 also has no RMT peripheral, so the NeoPixel HAL falls back to the SPI-backed `led_strip` driver automatically on chips where it's built.

### ESP32-P4 notes

The P4 build assumes the on-board co-processor is an ESP32-C6 wired the same way as Espressif's ESP32-P4-Function-EV-Board (SDIO 4-bit on GPIO14-19 plus reset on GPIO54). This is the official Espressif reference layout that the currently supported boards copy verbatim.

#### Picking a P4 board

P4 boards differ in flash size and partition layout, so the build selects a board-specific overlay from `boards/`. The overlay is chosen with an `idf.py` argfile passed *before* `set-target`:

```bash
# Waveshare ESP32-P4-WIFI6-Touch-LCD-4B (32 MB flash, 4" 720x720 MIPI-DSI panel)
idf.py @boards/waveshare_lcd_4b.cfg set-target esp32p4

# DFRobot DFR1172 FireBeetle 2 ESP32-P4 (16 MB flash, headless)
idf.py @boards/dfr1172_firebeetle.cfg set-target esp32p4
```

#### Other P4 boards

For a new board, copy one of the files in `boards/` (the `.defaults` overlay, its `.cfg` argfile, and a partition CSV) and adjust the flash size + partition table. If the C6 is on different pins or talks over SPI instead of SDIO, also override `CONFIG_ESP_HOSTED_P4_DEV_BOARD_FUNC_BOARD` and set the transport pins via `idf.py menuconfig` -> *Component config -> ESP-Hosted config*. If you have rev 3.0+ silicon, drop `CONFIG_ESP32P4_SELECTS_REV_LESS_V3` / `CONFIG_ESP32P4_REV_MIN_100` from `sdkconfig.defaults.esp32p4`.

## Writing WASM Apps

Every Wendy app is a `.wasm` guest. Wendy resolves host imports from the `"wendy"` module, loads the guest into WAMR, and starts it using the entrypoint model produced by your toolchain. C, Rust, WAT, and older Swift guests usually export `_start()`. New Swift guests should prefer `@main` on a type that conforms to `WendyLiteApp`.

Pick your language below.

### Swift

Wendy Lite ships a **WendyLite** SwiftPM library. Add it as a dependency and `import WendyLite`.

**Requirements:**

- Install `swiftly` from [swift.org/install](https://www.swift.org/install/)
- Install and select Swift 6.3.1:

```bash
swiftly install 6.3.1
swiftly use 6.3.1
```

- Install the Swift SDKs for WebAssembly: [Getting Started with Swift SDKs for WebAssembly](https://www.swift.org/documentation/articles/wasm-getting-started.html)

```bash
swift sdk install https://download.swift.org/swift-6.3.1-release/wasm-sdk/swift-6.3.1-RELEASE/swift-6.3.1-RELEASE_wasm.artifactbundle.tar.gz --checksum bd47baa20771f366d8beed7970afaa30742b2210097afd15f85427226d8f4cf2
```

- Verify the installed SDK IDs with `swift sdk list`. Wendy Lite uses the Embedded Swift SDK, typically `swift-6.3.1-RELEASE_wasm-embedded`

**1. Create your app package:**

```
mkdir MyApp && cd MyApp
```

```swift
// Package.swift
// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/wendylabsinc/wendy-lite.git", branch: "main"),
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
                    "-Xlinker", "--allow-undefined",
                    "-Xlinker", "--initial-memory=65536",
                    "-Xlinker", "--table-base=1",
                    "-Xlinker", "--strip-all",
                    "-Xlinker", "--export=malloc",
                    "-Xlinker", "--export=free",
                    "-Xlinker", "--export=wendy_handle_callback",
                    "-Xlinker", "-z", "-Xlinker", "stack-size=8192",
                ]),
            ]
        )
    ]
)
```

**2. Write your app:**

```swift
// Sources/MyApp/AppMain.swift
@_spi(ExperimentalCustomExecutors)
import WendyLite

// Opt into the executor optimized for Wendy Lite
typealias DefaultExecutorFactory = WendyExecutorFactory

@main
struct MyApp: WendyLiteApp {
    let clock = WendyClock()
    var isOn = false

    mutating func setup() async {
        GPIO.configure(pin: 8, mode: .output)
    }

    mutating func loop() async {
        GPIO.write(pin: 8, level: isOn ? 1 : 0)
        isOn.toggle()
        try? await clock.sleep(for: .milliseconds(500))
    }
}
```

The `@_spi(ExperimentalCustomExecutors)` import and `DefaultExecutorFactory` typealias install a cooperative executor that minimizes your app's I/O latency in the WASM environment. This relies on Swift features that are currently unstable but it is recommended for improved performance.

**3. Build:**

```bash
swiftly run +6.3.1 swift build \
    --swift-sdk swift-6.3.1-RELEASE_wasm-embedded \
    --triple wasm32-unknown-wasip1 \
    -c release
```

Put one-time startup work in `setup()` and steady-state behavior in `loop()`. Use `WendyClock` instead of `Task.sleep()`, which is unavailable in Embedded Swift.

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
wendy-lite = { git = "https://github.com/wendylabsinc/wendy-lite.git" }

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
```

## Async Callbacks

Some APIs accept a `handler_id` parameter for async events (GPIO interrupts, timers, BLE events).

For Swift apps built with `WendyLite`, conform your `@main` type to `WendyLiteApp`. Wendy Lite exports `wendy_handle_callback` for you and pumps callbacks in the background so `WendyClock.sleep` and other async APIs can resume without manual `System.yield()` calls.

Low-level C and Rust guests still receive callbacks by exporting a handler function and periodically yielding:

```c
// C
void wendy_handle_callback(int handler_id, int arg0, int arg1, int arg2) {
    // Dispatched when you call sys_yield()
}
```

```rust
// Rust
#[no_mangle]
pub extern "C" fn wendy_handle_callback(handler_id: i32, arg0: i32, arg1: i32, arg2: i32) {
    // Dispatched when you call sys::yield_now()
}
```

For manual guests, callbacks are dispatched when your app calls `sys_yield()` / `sys::yield_now()`.

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
