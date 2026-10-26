# XIAO ESP32-S3 Sense camera throughput

The native XIAO SensorLink profile prioritizes continuous video delivery. It
captures 640×480 JPEG at the camera driver's quality setting 24 (higher values
mean stronger compression), uses a 32,768-byte TCP send buffer and the rated
240 MHz CPU profile, and disables Wi-Fi modem sleep on this board.

## Transport changes

SensorData previously queued the wire header, protobuf prefix and payload as
three separate transmit nodes. On the XIAO's TLS connection, the small framing
writes added overhead before each JPEG chunk. The XIAO path now copies these
parts into one contiguous staging buffer and submits one transmit node per
SensorData message. The encoded protocol bytes and chunk sequencing are
unchanged. Other boards retain their existing borrowed-payload path.

The staging buffer is at most 10 KiB per in-flight frame. It is reused across
that frame's messages and remains owned until transport completion, including
cancellation, disconnect and failed transmission. It is freed before notifying
the producer that its frame can be released. TLS and peer authentication are
unchanged.

## Hardware observations (2026-10-23)

Two XIAO ESP32-S3 Sense boards streamed simultaneously through SensorLink to a
Qualcomm IQ9 and then through the normal Wendy Cloud camera viewer. Baseline
distinct decoded frame rates were about 3.0 and 1.9 FPS. Timing instrumentation
showed camera-buffer waits around 1 ms and frame-send times of 295–366 ms at
approximately -43 dBm Wi-Fi signal. Enlarging the TCP send buffer alone raised
one camera to about 6 FPS; immediate TCP acknowledgements and disabling modem
sleep alone did not resolve the bottleneck.

With the combined changes in private firmware 0.11.104, a 60.029-second
simultaneous test passed six consecutive 10-second windows on both cameras:

| Measurement | Camera 1 | Camera 2 |
|---|---:|---:|
| Mean distinct incoming FPS | 20.81 | 21.61 |
| Slowest 10-second window | 19.688 | 20.18 |
| Browser image-load FPS, independently sampled for 68.159 seconds | 20.29 | 21.02 |
| JPEG dimensions parsed from frames | 640×480 | 640×480 |

Conditions and limits:

- Both pairings subscribed only to `camera`. Audio exclusion was runtime
  pairing configuration; the firmware still supports the microphone.
- No YOLO or other inference ran in this test. The later CPU inference demo
  reduced throughput; these measurements are video-only results.
- The previous capture profile was 800×600 at quality 12. The result includes
  fewer pixels and stronger JPEG compression, so it is not an equal-quality
  transport-only comparison. Scene content also affects JPEG size.
- Continuous Wi-Fi and the higher CPU clock increase power demand. Larger TCP
  and staging buffers use additional memory. Battery and long-duration thermal
  behavior were not qualified by this one-minute test.
- Temporary timing instrumentation and the installation bridge were removed
  before final measurement. Only application OTA partitions were updated; the
  installed private application SHA-256 was
  `6114572a383e60ed61449ac17b36f091c1937627569cceb69159529f4de16539`.

To reproduce the rate check, run both camera-only streams simultaneously,
count distinct decoded image hashes in each consecutive 10-second window for
at least one minute, verify actual JPEG dimensions and freshness, and record
both per-window rates and browser delivery separately. Do not count repeated
frames or an intended sender rate as delivered FPS.

## Host regression checks

The framing suite builds both the original and XIAO coalesced paths. It checks
exact protocol bytes, a single queued transmit node on XIAO, ordering,
independent links, cancellation, deferred completion, disconnect, failure and
concurrent producers. The SensorLink suite covers sensor manifests, buffer
ownership, lifecycle and concurrent camera/audio senders.

```sh
cmake -S components/wendy_com/tests -B /tmp/wendy-com-tests \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build /tmp/wendy-com-tests
ctest --test-dir /tmp/wendy-com-tests --output-on-failure
cmake -S components/wendy_sensor_link/tests -B /tmp/wendy-sensor-tests \
  -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/wendy-sensor-tests
ctest --test-dir /tmp/wendy-sensor-tests --output-on-failure
```

Host tests verify framing and lifecycle, not hardware throughput. The measured
private firmware was built with official ESP-IDF v6.0.3; these source changes
contain no release version override or firmware binary.
