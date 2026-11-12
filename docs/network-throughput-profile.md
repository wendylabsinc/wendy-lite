# PSRAM network throughput qualification profile

`boards/network_throughput_psram.defaults` is an opt-in lab profile for ESP32-C5
and ESP32-S3 boards with working PSRAM. It increases TCP buffering and keeps
Wi-Fi queues bounded. Existing board defaults do not select it. No hardware
throughput or latency improvement is claimed until the comparison below runs
on the intended board and application.

## What changes

| Resolved setting | Profile value |
|---|---:|
| TCP send buffer | 32,768 bytes per socket |
| TCP receive window | 32,768 bytes per socket |
| TCP receive mailbox | 32 entries per socket |
| TCP/IP mailbox | 64 entries |
| Wi-Fi static RX / TX buffers | 8 / 8 |
| Wi-Fi dynamic RX / cached TX buffers | 32 / 32 |
| Wi-Fi receive block-ACK window | 6 |

The XIAO native board already has a 32,768-byte send buffer. Its baseline
receive window is 5,760 bytes with a six-entry TCP receive mailbox. The profile
therefore increases receive capacity rather than duplicating its send tuning.
The C5 PSRAM board keeps its existing two-slot BLE receive-credit configuration.

A 32-entry TCP mailbox accommodates the configured receive window with the
1,440-byte MSS. Wi-Fi static RX capacity exceeds the block-ACK window. Wi-Fi
buffer counts are finite; zero dynamic RX buffers would mean unlimited
allocation and is rejected. Static DMA buffers remain internal while the
board's existing PSRAM allocation policy handles eligible Wi-Fi/lwIP storage.
IRAM placement, CPU frequency and PSRAM wiring/speed stay board-specific.

The profile requires PSRAM at boot. In particular, the C5 board's ordinary
`SPIRAM_IGNORE_NOTFOUND` fallback is disabled for this experiment. Otherwise
large network allocations could fall back into limited internal memory.
The resolved configuration must retain at least 32 KiB of internal reserve,
an internal allocation threshold of at most 1 KiB and no more than 24 lwIP
sockets. The XIAO retains its larger 96 KiB reserve; the C5 retains 32 KiB.
These checks are configuration limits, not proof of runtime heap headroom.

At 24 active sockets, the configured send and receive payload capacities alone
can total 1.5 MiB. Packet metadata, mailbox entries, TLS storage, application
buffers and Wi-Fi copies consume additional memory. Measure concurrent-use
headroom, especially with camera DMA, BLE and WASM enabled. Larger queues can
also increase latency when a consumer falls behind.

## Build and verify

Use ESP-IDF 6.0.3 and a fresh build directory and sdkconfig for each comparison.
Appending defaults does not override an existing sdkconfig. With the profile
flag enabled, the build checks resolved values and fails with the mismatched
setting if an old window, mailbox or Wi-Fi buffer value remains.

For the XIAO native camera board:

```sh
idf.py -B build/xiao-net-profile \
  -D SDKCONFIG=build/xiao-net-profile/sdkconfig \
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/seeed_xiao_esp32s3_native.defaults;boards/network_throughput_psram.defaults' \
  -D IDF_TARGET=esp32s3 build
```

For a C5 with the PSRAM module described by its board overlay, using native
firmware to isolate networking from optional WASM workloads:

```sh
idf.py -B build/c5-net-profile \
  -D SDKCONFIG=build/c5-net-profile/sdkconfig \
  -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/esp32c5_generic_native.defaults;boards/wendy_net.defaults;boards/esp32c5_net_psram.defaults;boards/wendy_net_8mb.defaults;boards/network_throughput_psram.defaults' \
  -D IDF_TARGET=esp32c5 build
```

Build the baseline in a separate fresh directory with the same command and the
last overlay omitted. Validate a generated configuration independently with:

```sh
cmake -D WENDY_NETWORK_CONFIG="$PWD/build/xiao-net-profile/config/sdkconfig.cmake" \
  -P cmake/network_profile.cmake
```

The profile rejects C6, other unsupported targets, SRAM-only configurations and
constrained mesh configurations. A normal C6 build with the profile disabled
keeps its existing limits. Disabling the profile flag in an already tuned
sdkconfig does not restore baseline values; build a fresh baseline instead.

## Compilation evidence

The official `espressif/idf:v6.0.3` image built both native profile combinations
above. Each generated `config/sdkconfig.cmake` passed the standalone check.
The resolved output was:

```text
XIAO: TCP 32768/32768, RX mailbox 32, Wi-Fi RX/TX 8/8, internal reserve 98304
C5:   TCP 32768/32768, RX mailbox 32, Wi-Fi RX/TX 8/8, internal reserve 32768
```

The XIAO application occupied `0x171fb0` bytes with 62% of its application
partition free. The C5 application occupied `0x1a7170` bytes with 34% free.
These are flash partition margins, not runtime memory measurements. The Wi-Fi
host suite passed all five CTest entries under AddressSanitizer and
UndefinedBehaviorSanitizer, including ten Python configuration-guard cases.

The constrained C6 native build also passed with these defaults:

```text
sdkconfig.defaults;boards/esp32c6_generic_native.defaults;boards/wendy_net.defaults;boards/esp32c6_net.defaults;boards/wendy_net_8mb.defaults
```

Its resolved configuration kept the profile disabled, TCP send/receive at
5,760 bytes, MSS at 536 bytes and Wi-Fi static/dynamic RX counts at 4/16.
Appending the throughput overlay in a fresh C6 configuration failed before
compilation with `PSRAM throughput profile supports only ESP32-C5 and ESP32-S3`.

## Hardware comparison

Alternate baseline and profile firmware at least three times on the same board.
Keep the application, mesh peer count, AP/channel, signal strength, supply,
CPU clock and temperature comparable. Save both resolved sdkconfigs and logs.
Verify PSRAM initialization before each run.

Measure these workloads through the actual authenticated WendyCom or mesh app
path, in both upload and download directions:

1. A sustained 32 MiB transfer, first alone and then alongside ten small
   management requests per second. Report useful throughput and p50/p95/p99
   management round-trip latency separately.
2. Camera plus microphone where the board has those sensors. Count distinct
   complete frames, frame age and audio gaps. Preserve the same resolution,
   quality and subscriptions across runs.
3. Concurrent connections approaching the application's expected peak, including
   cloud and BLE when used. Record internal and PSRAM free memory, minimum free
   internal memory, largest internal/DMA free blocks, allocation failures and
   reconnects. Window capacity is not the same as actual allocated memory.
4. Repeat on direct Wi-Fi and a LAN mesh route, then with network delay and loss
   representative of the deployment. Include a slow reader to expose queueing.

Select production defaults only after a repeatable throughput benefit, acceptable
tail latency and sufficient runtime headroom are observed together. The host
configuration tests and firmware build prove selection and compilation; they do
not qualify radio performance or the board's physical PSRAM.
