# Mosaico dashboard

A native Wendy Lite sample for ESP-Mosaico. The 480 × 480 touch screen shows an
acceleration-based tilt indicator, accelerometer and gyroscope readings,
enrollment status, Wi-Fi and Cloud connection state, uptime, and free internal
heap. Tap **Pause motion** to freeze the motion display or **Zero tilt** to set
the current pose as the tilt reference. Device status continues updating while
motion is paused. The indicator is not a calibrated orientation estimate.

The dashboard opens on **Mesh**. Tap **Motion** to use the tilt indicator.
The Mesh page refreshes once per second and shows the authenticated direct peer,
its carrier, and live signed members with their remaining lease time. The link
is amber during the cold-boot replay barrier and green when mesh IP is active.
Disconnects, enrollment resets, and expired identity or route leases remove the
link and members. Signed membership does not describe remote adjacency, so the
page only draws the directly observed link. The scrollable roster holds up to
32 members and excludes withdrawn or ambiguous address claims.

Wendy owns Wi-Fi, BLE, USB-C management, and enrollment. The sample starts
`wendy_core_init()` once and uses the board package for the display, touch, and
IMU. It initializes the display before networking to reserve its DMA resources
and shows a startup message while Wendy initializes. LVGL uses FreeRTOS locks
and the system allocator so UI allocations can use PSRAM. A four-line internal
draw buffer is reserved at startup, avoiding per-flush DMA bounce allocations
after the camera, audio and network drivers fragment the heap. Audio reserves
mono DMA buffers at startup, and Wi-Fi reserves eight transmit buffers to leave
room for camera capture and TLS. SensorLink
initializes next, before networking. A missing camera, microphone, display, or
IMU leaves Wendy device management running.

## Hardware and dependencies

The pinned [ESP-Mosaico BSP](https://github.com/esp-mosaico/esp-mosaico-bsp/tree/5f88b91e1be055d1d3674364123b2779a1758377)
supports board revisions 1.0 and 1.2, with 1.1 using the 1.2 mapping. It detects
the revision from eFuse. An unknown revision stops dashboard initialization.
See the [hardware guide](https://documentation.espressif.com/esp-dev-kits/en/latest/esp32s31/esp-mosaico/index.html)
for power, connectors, and entering download mode.

This sample uses 16 MB program flash, enables PSRAM for the display, and uses
Wendy's 8 MB OTA partition offsets with two 3,997,696-byte app slots. The sample's
`partitions.csv` adds a 256 KiB crash-dump partition at `0x800000`; the remaining
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

With a CLI that supports `wendy-idf.json`, run the dashboard from this directory:

```sh
wendy run --device wendy-lite:PORT --yes --detach
```

The project pins the same ESP-IDF container used in CI. Docker must be running.
Wendy builds the app, transfers it through USB management into the inactive OTA
slot, and reboots. The board must already have the Mosaico partition layout.
The default EIM toolchain remains available for projects without this file.
The sample confirms an OTA image after Wendy and the dashboard initialize.
Its shutdown handler performs a full system reset to avoid the pinned preview
SDK's CPU-only restart stalling on this board.

## Join the mesh

Enroll Mosaico in the same tenant as the other peers and configure Wi-Fi through
Wendy USB or BLE management. Native Wendy Net support is compiled into this
profile but remains off until enabled through WendyCom configuration.

Peers discover one another on mDNS and BLE, then authenticate with the enrolled
identity. The signed binary protocol and Babel routing are the same as WendyOS.
The dashboard shows runtime state, active carrier count, and managed RAM use;
the Wendy topology UI supplies the complete verified graph. SensorLink remains
available through the existing physical and native mesh management interfaces.
See [native Wendy Net](../../docs/wendy-net.md) for profiles and constraints.

## Install and connect

Once the Mosaico firmware is published, use a matching CLI and choose
**ESP-Mosaico** in the install picker:

```sh
wendy install
```

From the powered-off state, keep USB connected, hold BOOT, briefly press POWER,
then release BOOT. The installer recognizes the S31 ROM and uses its watchdog
reset to start the dashboard after flashing. The catalog entry becomes available
in the installer when the release pipeline publishes its firmware manifest.

For development before publication, use the direct flash instructions below.
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

Mosaico's Type-C connector exposes two USB CDC serial interfaces. Interface 0
is the Wendy console and physical management connection, including Wi-Fi setup
and enrollment. Interface 1 reports startup stage, uptime, reset reason, and
available memory and the largest free DMA block once per second, plus the saved
crash location after a panic.
Diagnostics include the running OTA slot and ELF fingerprint so an upload can
be checked after reboot. Diagnostic messages never share the binary management stream. The separate
USB Serial/JTAG transport is disabled in this sample.

Use the first CDC serial interface explicitly with a matching Lite-capable CLI:

```sh
wendy device info --device wendy-lite:PORT
wendy device wifi connect --device wendy-lite:PORT --ssid SSID --password PASSWORD
wendy cloud enroll-device --device wendy-lite:PORT --name mosaico
```

The CLI must support UUID Lite enrollment for mesh. Log in to the router's tenant
first. Supply your deployment's trust bundles and time endpoint when needed, as
described in [the enrollment guide](../../docs/cloud-enrollment.md).

BLE also accepts Wi-Fi-only configuration updates through the existing Lite
management connection. Enrollment and trust changes still require physical USB.
Use continuous `wendy discover` for Lite BLE discovery; the CLI's legacy timed
Bluetooth scan does not enumerate Lite boards. Wi-Fi changes take effect after
the CLI reboots the board. Before enrollment, BLE setup uses the existing
anonymous TLS policy; afterward it requires a same-tenant operator identity.
The dashboard displays enrollment status and does not collect credentials.

## SensorLink camera and microphone

The dashboard includes the onboard ES8311 microphone and an optional Mosaico
camera module in the left slot. SensorLink advertises only sensors that
initialize successfully. The camera module is discovered through its EEPROM;
unidentified expansion boards are not driven as cameras.

The camera provides 1280x720 MJPEG using the S31 hardware JPEG encoder. The
microphone provides 16 kHz, 16-bit mono PCM. Both can stream concurrently. Capture
starts on subscription and stops when the client unsubscribes or disconnects.
The board package owns the camera pin mapping, power, and shared audio bus.
USB Serial/JTAG is disabled because GPIO33 is camera D2; USB-C management uses
the separate OTG controller.

```sh
wendy device camera list --device wendy-lite:PORT
wendy device camera view --device wendy-lite:PORT --id 0
wendy device audio list --device wendy-lite:PORT
wendy device audio listen --device wendy-lite:PORT --id 1
```

Use separate network connections for concurrent viewers; two CLI processes
cannot open the same USB serial port. Existing builds must enable
`CONFIG_WENDY_SENSOR_LINK_MOSAICO=y` and disable
`CONFIG_USJ_ENABLE_USB_SERIAL_JTAG` in their saved sdkconfig.

## Validation

The CI build checks that mesh, Wi-Fi/BLE fallback, and the custom IPv6 route hook
are enabled alongside networking, enrollment, PSRAM, display, touch, and the IMU.
The topology host test covers lease expiry, withdrawals, unsigned entries,
address collisions, bounded output, and preservation of replay receipts.
Discovery tests cover tenant and self filtering, malformed advertisements,
address filtering, duplicate candidates, bounded output, and random ordering.

On hardware, enroll and connect Wi-Fi with at least two discoverable routers. Check the
replay countdown, green link after IP activation, and member lease updates.
Disconnect the selected router and confirm that the link and roster clear,
then verify that another authenticated router is selected. Switch between Mesh and Motion, scroll the member list, and
check that Pause motion leaves mesh and device status updates running.

Validated on a USB-connected Mosaico revision 1.2 with ESP32-S31 revision 0.0.
The flashed image passed hash verification, USB diagnostics reached
`dashboard running` and stayed up, and the user confirmed the display and
Mesh/Motion tab switching work. A saved crash dump identified a NimBLE startup
ordering bug; the BLE regression tests now require host initialization before
setting the GAP name. All four BLE configurations and 17 mesh, configuration,
permissions, and USB transport host tests pass.

Live USB enrollment, authenticated cloud logs, and automatic mesh joining were
verified on this board. The user confirmed the peer and topology on the display.
Motion calibration and router failover still need hardware validation.

SensorLink validation on the same board captured and decoded 53 complete
1280x720 JPEG frames and 8.7 seconds of nonzero mono PCM. A simultaneous
subscription delivered both channels in two sessions, including reconnecting
after closing an active connection and then explicitly unsubscribing both
channels. USB diagnostics remained at `dashboard running`. All 19 SensorLink
host scenarios passed, including the Mosaico concurrency and cleanup cases.
