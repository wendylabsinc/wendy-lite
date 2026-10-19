# SensorLink host tests

Run without ESP-IDF or hardware:

```sh
cmake -S components/wendy_sensor_link/tests -B /tmp/wendy-sensor-link-tests
cmake --build /tmp/wendy-sensor-link-tests
ctest --test-dir /tmp/wendy-sensor-link-tests --output-on-failure
```

The tests compile the production initialization, delegate, and sender code.
Camera, microphone, FreeRTOS, and communication operations use host stubs.
Each scenario runs in a separate process so initialization uses its normal
public entry point without test-only reset functions.

Coverage includes partial sensor availability, initialization cleanup and retry,
channel formats, competing subscriptions, client-specific cancellation, and
waiting for frame completion before releasing camera buffers or stopping audio.
The concurrent scenarios build once per board, run both sender tasks on host
threads, and verify concurrent camera/audio ownership, independent disconnects,
audio timestamps, and cleanup when creation of the second sender fails.
Catch-up tests check that an XIAO audio frame carries the samples queued behind
its block, up to the frame's capacity.
Counter tests check cancellation completions, queue refusal, failed capture,
duration totals/maxima, and a completion that races ahead of submission return.
Cancellation tests require stream-end before releasing a pending frame, and
require the frame callback before freeing its buffer or stopping capture.
The tests do not validate hardware pin configuration, capture drivers, or task
scheduling on the device.
