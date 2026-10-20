# Wendy Lite

Wendy Lite runs applications on ESP32 microcontrollers. Native applications use C/C++ and ESP-IDF. Optional WebAssembly support runs applications compiled from Swift, Rust, C/C++, AssemblyScript or WAT.

The Wendy host firmware exposes a comprehensive set of hardware APIs through WASM imports — GPIO, I2C, SPI, UART, RMT, NeoPixel, BLE, WiFi, sockets, TLS, USB, NVS storage, timers, and OpenTelemetry.

Wendy Lite also supports native applications, written in C and C++ and built using the ESP-IDF tools and API.

Build with ESP-IDF 6.0.3, or ESP-IDF 6.1 for the ESP32-S31 preview target.
Initialize nested dependencies with
`git submodule update --init --recursive`. The pinned esp-pqc component supplies
mbedTLS 4, ML-DSA-65 operator identities, and ML-DSA-65/87 CA verification;
P-256 device keys remain supported.
CI uses `espressif/idf:v6.0.3` for existing targets and `espressif/idf:v6.1`
for ESP32-S31. To build ESP32-C6 with the same container:

```sh
docker run --rm -v "$PWD:/project" -w /project espressif/idf:v6.0.3 \
  idf.py -B build-idf6 -D SDKCONFIG=sdkconfig.idf6 \
  -D SDKCONFIG_DEFAULTS=sdkconfig.defaults -D IDF_TARGET=esp32c6 build
```

Use a fresh build directory and configuration when upgrading from ESP-IDF 5.

An opt-in [signed mesh leaf profile](docs/signed-mesh-leaf.md) is available for
native ESP32-S3 builds with PSRAM. It connects to one pinned Linux mesh router
and has a 125-second startup quarantine. The source and host tests are available;
hardware validation is still pending.

## Optional WASM support

Firmware builds omit the WASM runtime by default. To enable it on a supported
board, append `boards/wasm.defaults` after the base and board defaults in
`SDKCONFIG_DEFAULTS` before configuring a fresh build. For example, on ESP32-C6:

```sh
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/wasm.defaults' set-target esp32c6
idf.py build
```

Existing `sdkconfig` files retain their choices. Configure a fresh build to pick
up the new defaults, including disabled WASM callbacks and host API exports.
ESP32-C61 and ESP32-S31 have no supported WASM runtime. Disabling
WASM does not change partition layouts or reclaim existing WASM data partitions.

The firmware catalog publishes only native OTA variants: generic ESP32-C5,
ESP32-C6, ESP32-C61, ESP32-S3 and preview ESP32-S31, plus Seeed XIAO ESP32S3,
M5Stack StampS3 and ESP32-S31-Korvo-1 V1.1.
Legacy WASM-layout images, including the ESP32-P4 images, are available only as
manual builds.

## Optional Bluetooth support

Bluetooth is enabled by default. PKI-enrolled boards advertise their identity
and accept same-tenant operators over TLS 1.3 on BLE L2CAP. Interactive
`wendy discover` reads the GATT identity service to list these boards, including
when Wi-Fi is unavailable. Enrollment itself still requires USB.

To omit the BLE transport and its controller/host
stack, append `boards/no-ble.defaults` last, after any board or WASM defaults:

```sh
idf.py -B build-no-ble -D SDKCONFIG=sdkconfig.no-ble \
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/no-ble.defaults' set-target esp32c6
idf.py -B build-no-ble -D SDKCONFIG=sdkconfig.no-ble build
```

Use a new sdkconfig filename, or disable `Component config > Bluetooth` in
`idf.py menuconfig` for an existing configuration. Defaults do not override an
existing sdkconfig. Disabling only the WendyCom BLE transport does not disable
the entire Bluetooth stack.

USB and Wi-Fi remain available, including Cloud access when enabled. The board
will not advertise or accept connections over BLE, and WASM BLE exports are
unavailable. The profile can be combined with `boards/wasm.defaults`; put
`boards/no-ble.defaults` last.

## Supported Hardware

Wendy Lite has firmware configurations for six ESP-IDF targets. ESP32-S31 is
a preview target. The Korvo-1 profile has passed the hardware checks described
in the [ESP32-S31 notes](#esp32-s31-notes).

| Target | Reference board (Espressif dev kit) | Wi-Fi / BT |
|---|---|---|
| `esp32c5` | Espressif ESP32-C5-DevKitC | Native (2.4 / 5 GHz Wi-Fi 6 + BLE) |
| `esp32c6` | Espressif ESP32-C6-DevKitC | Native Wi-Fi 6 + BLE |
| `esp32c61` | Espressif ESP32-C61-DevKitC | Native Wi-Fi 6 + BLE — no WASM app support yet, see [ESP32-C61 notes](#esp32-c61-notes) |
| `esp32p4` | None (see [ESP32-P4 notes](#esp32-p4-notes)) | Via on-board ESP32-C6 over SDIO (ESP-Hosted) |
| `esp32s3` | None | Native Wi-Fi + BLE |
| `esp32s31` | Generic profile or ESP32-S31-Korvo-1 V1.1 | Native Wi-Fi + BLE; native apps only, see [ESP32-S31 notes](#esp32-s31-notes) |

Each target except `esp32p4` has a generic board configuration in
`boards/<target>_generic*.cfg` that uses 4 MB flash and leaves PSRAM disabled.
Where WASM is supported and enabled, its pool uses the system allocator.
ESP32-S31's generic profile assumes at least 4 MB of flash and does not configure
board-specific peripherals. ESP32-P4 requires a board-specific overlay; see
[ESP32-P4 notes](#esp32-p4-notes).

Beyond the generic boards, Wendy Lite has overlays for the following boards, each with its own flash size, PSRAM, and peripherals:

| Board | Target | Flash | PSRAM | Notes |
|---|---|---|---|---|
| Waveshare ESP32-P4-WIFI6-Touch-LCD-4B | `esp32p4` | 32 MB | 32 MB | Wi-Fi/BT via on-board ESP32-C6 (SDIO/ESP-Hosted); 4″ 720×720 MIPI-DSI touch panel; WAMR pool: 24 MiB from PSRAM |
| DFRobot FireBeetle 2 ESP32-P4 (DFR1172) | `esp32p4` | 16 MB | 32 MB | Wi-Fi/BT via on-board ESP32-C6 (SDIO/ESP-Hosted); headless; WAMR pool: 24 MiB from PSRAM |
| Seeed Studio XIAO ESP32S3 | `esp32s3` | 8 MB | 8 MB | Native Wi-Fi/BT; native app support (OTA partition layout); bundled SensorLink camera/microphone for the Sense expansion board; no WASM app support |
| M5Stack StampS3 | `esp32s3` | 8 MB | – | Native Wi-Fi/BT; native app support (OTA partition layout); no WASM app support |
| Espressif ESP32-S31-Korvo-1 V1.1 | `esp32s31` | 16 MB | 16 MB | QIO flash at 80 MHz, octal PSRAM at 200 MHz; native apps; OV3660 camera and ES8389 microphones tested together over UART; preview |

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

ESP32-S31 uses ESP-IDF 6.1 and the preview option. Start with a separate build
directory and sdkconfig:

```sh
idf.py --preview -B build/esp32s31 -D SDKCONFIG=build/esp32s31/sdkconfig \
  @boards/esp32s31_generic_native.cfg set-target esp32s31
idf.py --preview -B build/esp32s31 -D SDKCONFIG=build/esp32s31/sdkconfig build
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

### Seeed XIAO ESP32S3 SensorLink

The `seeed_xiao_esp32s3_native` board overlay and released
`esp32s3_seeed_xiao_native` firmware bundle SensorLink support for the XIAO
ESP32S3 Sense expansion board. Channel 0 streams 800×600 MJPEG video. Channel 1
streams signed 16-bit little-endian PCM audio at 16 kHz, mono, in chunks of
20 ms or more. The two are separate inputs and can stream at the same time,
to one client or to two.

After enrolling the device, use a Wendy CLI with SensorLink camera/audio support:

```sh
wendy device camera view --device wendy-lite:<device-hostname>.local
wendy device audio list --device wendy-lite:<device-hostname>.local
wendy device audio listen --device wendy-lite:<device-hostname>.local --id 1
```

USB also works with `--device wendy-lite:/dev/cu.usbmodem101`, using your board's
serial port. Streaming stops on unsubscribe or disconnect. Sensors that fail to
initialize are omitted from the manifest, and device management still starts.
The PDM microphone has no presence detection, so a board without the Sense
expansion can still advertise its audio channel without producing useful audio.

Camera initialization runs before networking to reserve contiguous DMA memory.
JPEG buffers use PSRAM with direct PSRAM DMA disabled. The board overlay also
reserves 96 KiB of internal RAM for stacks and DMA and limits Wi-Fi buffers to
match the native SensorLink app. The Korvo-1 overlay has its own SensorLink backend;
other board overlays leave SensorLink disabled.
Configure a fresh build to apply these defaults, as described above.

### ESP32-C61 notes

No published `espressif/wasm-micro-runtime` release lists `esp32c61` as a supported target yet, so WASM app support -- and every component that exists solely to bridge native code to WASM guests (`wendy_wasm`, `wendy_hal`, `wendy_hal_export`, and everything `wendy_hal_export` pulls in) -- is dropped from the build on this target via `EXCLUDE_COMPONENTS` set conditionally on `IDF_TARGET` in the root `CMakeLists.txt`, rather than depending on an unofficial WAMR fork. This is target-conditioned in `CMakeLists.txt` itself (not the board argfile) so it applies however `esp32c61` gets selected as the target. The C61 also has no RMT peripheral, so the NeoPixel HAL falls back to the SPI-backed `led_strip` driver automatically on chips where it's built.

### ESP32-S31 notes

The [Mosaico dashboard sample](samples/mosaico_dashboard/README.md) adds a native
touch UI with live motion and Wendy device status for ESP-Mosaico. It uses a
separately pinned ESP-IDF 6.2 development toolchain required by the board package.

Use ESP-IDF 6.1 for ESP32-S31. The SDK still lists `esp32s31` as a
[preview target](https://github.com/espressif/esp-idf/blob/v6.1/tools/idf_py_actions/constants.py),
so pass `--preview` to `idf.py`. Other Wendy Lite targets remain on ESP-IDF 6.0.3.

The `esp32s31_generic_native` profile uses 4 MB of flash, DIO flash access at
40 MHz, and the existing `partitions.ota.csv` layout. Its two app slots are
1,900,544 bytes each. PSRAM stays disabled, including on modules that contain it.
These are conservative profile settings, not specifications for a particular
development board. Check the board's flash configuration before flashing.

S31 supports native applications only. The pinned
[`espressif/wasm-micro-runtime` 2.4.0~1](https://components.espressif.com/components/espressif/wasm-micro-runtime/versions/2.4.0~1)
does not list this target, so Wendy excludes the WASM runtime and its adapters.
The `boards/wasm.defaults` overlay cannot enable WASM on S31.

To build with the same SDK as CI:

```sh
docker run --rm -v "$PWD:/project" -w /project espressif/idf:v6.1 \
  idf.py --preview -B build/esp32s31 -D SDKCONFIG=build/esp32s31/sdkconfig \
  @boards/esp32s31_generic_native.cfg -D IDF_TARGET=esp32s31 build
```

With a local ESP-IDF 6.1 environment, flash and monitor the same build:

```sh
idf.py --preview -B build/esp32s31 -D SDKCONFIG=build/esp32s31/sdkconfig flash monitor
```

Use the generated `build/esp32s31/flash_args` if flashing individual images with
esptool. S31's bootloader starts at `0x2000`; do not reuse another target's offsets.

#### ESP32-S31-Korvo-1 V1.1

The `esp32s31_korvo_1_native` profile uses the
[Korvo-1 V1.1 board's 16 MB flash and 16 MB PSRAM](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s31/esp32-s31-korvo-1/user_guide.html).
It selects QIO flash at 80 MHz, octal PSRAM at 200 MHz, and `-O2` optimization.
Both HP cores run at the SDK's default 320 MHz. The 16 MB partition table gives
each OTA app slot 8,192,000 bytes. This layout differs from the generic profile,
so select the Korvo profile for the initial full flash before using its OTA images.
Use the generated `flash_args` when flashing individual images. ESP-IDF writes
a DIO boot header for the ROM and enables QIO in the second-stage bootloader,
so `flash_args` correctly reports `dio` even though the profile selects QIO.

Build and flash with a local ESP-IDF 6.1 environment:

```sh
idf.py --preview -B build/esp32s31-korvo-1 \
  -D SDKCONFIG=build/esp32s31-korvo-1/sdkconfig \
  @boards/esp32s31_korvo_1_native.cfg set-target esp32s31
idf.py --preview -B build/esp32s31-korvo-1 \
  -D SDKCONFIG=build/esp32s31-korvo-1/sdkconfig build
idf.py --preview -B build/esp32s31-korvo-1 \
  -D SDKCONFIG=build/esp32s31-korvo-1/sdkconfig flash monitor
```

The pre-production S31 revision 0.0 board requires ROM flashing with `--no-stub`;
esptool 5.6's stub failed at multiple baud rates. ESP-IDF 6.1's generated flash
configuration already selects ROM flashing for `idf.py flash`. When invoking
esptool directly, add `--no-stub` before `write-flash` and run from the build
directory so the paths in `@flash_args` resolve correctly. The `flash_args` file
contains image offsets and flash settings, but does not contain `--no-stub`.

The firmware uses PSRAM for large allocations and reserves 96 KiB of internal
RAM for DMA and task stacks. Wi-Fi uses the SDK's PSRAM defaults of 16 static RX
and 16 static TX buffers. TCP send and receive windows are 17,280 bytes, with
14 receive mailbox slots per socket. These are starting settings for concurrent
streaming and device management, not measured throughput claims. PSRAM XiP stays
disabled to avoid adding instruction traffic to the camera-buffer memory bus.

SensorLink channel 0 exposes 640×480 MJPEG from either supported DVP module.
OV3660 supplies JPEG directly; SC101IOT supplies YUV422 frames for the S31 JPEG
encoder. Channel 1 exposes both ES8389 microphone channels as stereo signed
16-bit little-endian PCM at 16 kHz. Camera and audio can stream together.
The source sensor rates are 25 fps for OV3660 and 15 fps for SC101IOT; actual
delivery rates depend on capture, encoding and the connection. The
[official board definitions](https://docs.espressif.com/projects/esp-board-manager/en/latest/references/boards/esp32_s31_korvo_1.html)
describe both camera variants. A missing sensor is omitted from the manifest.

Connect the Korvo's USB Type-C port marked UART to enroll or manage the board.
This port contains a USB-to-UART bridge connected to UART0, TX GPIO58 and RX
GPIO59. Wendy uses 115200 baud and the same console/management escape protocol
as its native USB transport. Select the bridge's serial device in the Wendy CLI.
The Type-C power port carries no data; the USB-A host port is not the programming
port. The ESP-IDF UART console provides boot and panic diagnostics. After
startup, Wendy's stdio hook owns ordinary input and output and suppresses
unframed logs while the serial port carries protocol traffic.

After enrollment through the bridge, use the device's Wi-Fi hostname for sensor
streaming. The 115200-baud serial connection is intended for setup and management:

```sh
wendy device camera view --device wendy-lite:<device-hostname>.local
wendy device audio listen --device wendy-lite:<device-hostname>.local --id 1
```

The optional SUB3 800×480 RGB display shows a native Wendy status page with
uptime, free PSRAM and Wi-Fi connection status. It uses one 768,000-byte PSRAM
framebuffer and refreshes status once per second. Touch input is not enabled.
To omit display startup, disable `CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1` in
this build's `menuconfig` and rebuild.

To omit onboard sensor startup, disable
`CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1` in this build's `menuconfig` and rebuild.
The generic S31 profile does not enable these peripherals. Speaker playback,
microSD, USB OTG and Ethernet are not initialized by the Korvo profile.
The generic S31 profile keeps the USB Serial/JTAG management transport; the
Korvo profile selects the UART bridge. Neither enables USB high-speed OTG.

Native apps can call ESP-IDF drivers and add ESP-DSP or ESP-NN components.
The firmware does not enable inference or DSP merely by selecting the board.
[S31 PIE/SIMD instructions run only on CPU1](https://github.com/espressif/esp-idf/blob/v6.1/docs/en/api-reference/system/freertos_idf.rst).
Place tasks that use those instructions on CPU1 and keep PIE calls out of ISRs
and critical sections. Wi-Fi keeps its SDK default CPU0 affinity; other tasks
retain their existing scheduling policy.

Before comparing performance, record the exact firmware revision, camera module,
transport and Wi-Fi signal strength. Measure camera alone, audio alone and both
together, then repeat during OTA or a TLS connection. Track delivered frames,
audio gaps, p95 latency, per-core load and the minimum free internal/DMA heap.
Compare the generic and Korvo profiles with the same non-sensor workload to
separate memory and compiler changes from the cost of sensor capture.

An opt-in benchmark build exercises internal RAM and PSRAM copies, then compares
an ESP-NN 1×1 convolution on CPU1 with its ANSI implementation. It validates the
outputs before reporting timings and emits `WENDY_BENCH` JSON records, including
heap snapshots every five seconds. Build it separately from the shipping profile:

```sh
idf.py --preview -B build/esp32s31-korvo-1-benchmark \
  -D SDKCONFIG=build/esp32s31-korvo-1-benchmark/sdkconfig \
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/esp32s31_korvo_1_native.defaults;boards/esp32s31_korvo_1_benchmark.defaults' \
  -D IDF_TARGET=esp32s31 build
idf.py --preview -B build/esp32s31-korvo-1-benchmark \
  -D SDKCONFIG=build/esp32s31-korvo-1-benchmark/sdkconfig flash monitor
```

The benchmark begins ten seconds after initialization. Use it to check memory
bandwidth and the optimized kernel on the actual board; it does not measure
end-to-end streaming performance. CI compiles this variant without publishing it
in the firmware catalog.

Save one boot's serial monitor output to a log file. Keep recording while camera
and audio stream to include the periodic heap samples, then summarize the saved
log:

```sh
python3 tools/korvo_benchmark.py /path/to/korvo.log
python3 tools/korvo_benchmark.py /path/to/korvo.log --json
```

Hardware validation on 2026-10-18 used a Korvo-1 V1.1 with rev0.0 silicon,
an OV3660 camera, ES8389 microphones and ESP-IDF 6.1. Boot confirmed 16 MB flash
in QIO mode at 80 MHz, 16 MB PSRAM at 200 MHz with the SDK memory test passing,
and a 320 MHz CPU clock. UART management reported native application support
and both sensors. A 30.6-second serial test of the normal firmware exercised simultaneous capture,
audio alone, camera restart, unsubscribe and management pings. All 19 completed
640×480 JPEGs and 67 stereo PCM blocks validated without ordering or timestamp
errors. Both microphone channels had nonzero samples without clipping. Two
unfinished camera frames were cancelled during unsubscribe. These counts reflect
the 115200-baud UART limit, not the sensors' full capture rates.

The SUB3 display was subsequently enabled and its Wendy status page and updating
uptime were visually confirmed on the board. A repeated 30.9-second UART test
with the display active validated 21 VGA JPEGs and 69 stereo PCM blocks, with
no ordering, timestamp or payload errors. Camera restart and management pings
also passed while the display continued refreshing.

The benchmark build measured the following with sensors initialized but idle,
before display support was enabled:

| Check | Measurement |
|---|---|
| Internal RAM copy, repeated 16 KiB block | 493.6 MiB/s |
| PSRAM copy, repeated 256 KiB block | 44.3 MiB/s |
| CPU1 INT8 1×1 convolution, ANSI | 3,873.4 µs per iteration |
| CPU1 INT8 1×1 convolution, optimized | 619.4 µs per iteration, 6.25× faster |
| Minimum free internal heap during the benchmark | 59,180 bytes |

Copy contents and convolution outputs matched their references. These are
single-run kernel measurements, not application throughput or latency guarantees.
The generic S31 profile remains build-tested only. Wi-Fi streaming, enrollment,
BLE connections, OTA rollback and the SC101IOT camera path still need hardware
validation. Playback and other uninitialized peripherals are outside this
profile's tested scope.

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

## Cloud enrollment

See [real PKI enrollment](docs/cloud-enrollment.md) for the PKI-enabled ESP32-C6 build,
USB setup with the Wendy CLI, and broker presence.
Cloud connections use the [TLS handoff and reconnect loop](docs/cloud-relay.md).
