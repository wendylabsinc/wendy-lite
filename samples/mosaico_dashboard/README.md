# Mosaico motion dashboard

A native Wendy Lite sample for ESP-Mosaico. The 480 × 480 touch screen shows an
acceleration-based tilt indicator, accelerometer and gyroscope readings,
enrollment status, Wi-Fi and Cloud connection state, uptime, and free internal
heap. Tap **Pause motion** to freeze the motion display or **Zero tilt** to set
the current pose as the tilt reference. Device status continues updating while
motion is paused. The indicator is not a calibrated orientation estimate.

Wendy owns Wi-Fi, BLE, USB Serial/JTAG, and enrollment. The sample starts
`wendy_core_init()` once and uses the board package for the display, touch, and
IMU. It does not require a camera or expansion board. An unavailable display or
IMU leaves Wendy device management running.

## Hardware and dependencies

The pinned [ESP-Mosaico BSP](https://github.com/esp-mosaico/esp-mosaico-bsp/tree/5f88b91e1be055d1d3674364123b2779a1758377)
supports board revisions 1.0 and 1.2, with 1.1 using the 1.2 mapping. It detects
the revision from eFuse. An unknown revision stops dashboard initialization.
See the [hardware guide](https://documentation.espressif.com/esp-dev-kits/en/latest/esp32s31/esp-mosaico/index.html)
for power, connectors, and entering download mode.

This sample uses 16 MB program flash, enables PSRAM for the display, and uses
Wendy's 8 MB OTA partition layout with two 3,997,696-byte app slots. The remaining
program flash is unused. The board's separate SPI NAND is not used.

The BSP requires ESP-IDF 6.2 development code. The build pins these dependencies:

| Dependency | Revision |
|---|---|
| ESP-IDF | `1c42e514c90ae621af33bde3b6ad3dac22edcbfd` |
| ESP-Mosaico BSP | `5f88b91e1be055d1d3674364123b2779a1758377` |
| Other managed components | `dependencies.lock` |

The sample reuses this checkout's esp-pqc dependency and reviewed TLS patches.
It enables ML-DSA-65 with fixed 16 KiB TLS receive buffers, as the main firmware
does. Generic ESP32-S31 firmware continues to use ESP-IDF 6.1.

## Build

From the repository root:

```sh
git submodule update --init --recursive
docker run --rm -v "$PWD:/project" -w /project/samples/mosaico_dashboard \
  espressif/idf@sha256:30b42a38415e918b1b14825ccf0e4c40e7910c5132618dcd12e3c45361be0943 \
  idf.py --preview build
```

The application is `samples/mosaico_dashboard/build/mosaico_dashboard.bin`.
The `Mosaico dashboard` GitHub Actions workflow builds the same project and
uploads the application, bootloader, partition table, and flash arguments.

With the pinned ESP-IDF checkout activated locally, the equivalent command is:

```sh
cd samples/mosaico_dashboard
idf.py --preview build
```

Build with ESP-IDF directly. Wendy CLI versions that still select ESP-IDF 5.x
cannot build this sample through `wendy run`.

## Install and connect

The first installation needs a full flash of the bootloader, partition table,
OTA metadata, and application. It replaces the factory application and uses a
different partition layout from the generic 4 MB S31 profile. Do not install
the app-only binary onto that layout through OTA.

Activate the pinned ESP-IDF environment, enter the board's download mode, and
use its serial port:

```sh
cd samples/mosaico_dashboard
idf.py --preview -p PORT flash
```

If the firmware was built in Docker, install esptool 5.6.0 on the host and use
the generated arguments from the build directory:

```sh
cd samples/mosaico_dashboard/build
esptool --chip esp32s31 --port PORT --no-stub write-flash @flash_args
```

Those arguments include S31's `0x2000` bootloader offset. Do not substitute
another target's flash offsets.

Mosaico's Type-C connector is USB OTG. Wendy's USB management transport uses
the separate USB Serial/JTAG header, with D+ on GPIO34 and D- on GPIO33. Use the
board's documented header connection for USB enrollment; console logs use UART.
Wi-Fi and BLE remain available through Wendy's existing device workflow.
The dashboard displays enrollment status and does not collect credentials.

## Validation

The firmware and merged flash image build with the pinned toolchain. The app
is 1,912,336 bytes, leaving 2,085,360 bytes per OTA slot. The resolved build
includes Wendy networking, enrollment, PSRAM, display, touch, and the IMU; it
excludes WASM.

No ESP-Mosaico hardware was used for validation. Touch alignment, motion axes,
display behavior, radio coexistence, and initial installation still need a
board check.
