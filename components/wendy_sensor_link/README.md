# Bundled SensorLink sources

`CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3` keeps the XIAO ESP32S3 Sense path:
800x600 MJPEG or 16 kHz mono PCM, with one active source at a time.

`CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1` targets the ESP32-S31-Korvo-1 V1.1.
It exposes camera channel 0/input 0 and microphone channel 1/input 1. Each channel
has its own sender and retains at most one frame until its transport completion
callback. The two channels can have different subscribing clients. A second
subscriber for an occupied channel receives `BUSY`; a two-channel request
reserves both channels only when both are available.

`wendy_sensor_link_get_stats()` snapshots lifetime counters for each channel.
It reports accepted submissions, submitted bytes, buffer-return completions,
immediate queue refusals, capture errors, and capture/completion duration totals
and maxima. A completion includes cancellation or a later transport refusal;
it does not establish successful delivery. Capture duration includes time spent
on failed reads and timeouts. Counters start at zero and are not reset when a
client disconnects.

The camera negotiates 640x480 JPEG from OV3660, or 640x480 UYVY from SC101IOT
and uses the S31 JPEG encoder at quality 80. It reserves two capture buffers
through `esp_video`, and one output buffer for hardware JPEG. Capture runs while
subscribed. A 100 ms dequeue timeout lets cancellation proceed when a sensor
stops delivering frames. Unsubscribe cancels the transport stream, waits for
any queued chunk to return its borrowed buffer, and then stops capture.

The ES8389 supplies 16 kHz interleaved stereo PCM in 20 ms blocks. The codec's
channel labels explicitly select the left and right microphones. The I2S path
uses TDM Philips format with clocks derived from XTAL, and the codec derives
its clock from BCLK. It does not enable the speaker amplifiers or DAC reference
loopback. The codec control device uses a 10 kHz I2C rate, matching Espressif's
S31 ES8389 test configuration; the camera uses 100 kHz on the shared bus.

Audio timestamps use read-completion time minus the 20 ms block duration.
When transmission falls behind, the I2S DMA queue can hold older samples, so
these timestamps do not provide precise capture timing or audio/video
synchronization. That requires capture timestamps and a buffer queue that
preserves them through transmission.

Dependencies are pinned to `esp_video` 2.5.0 and `esp_codec_dev` 2.0.0-beta4.
The latter provides the ES8389 channel mapping and TDM APIs used here. The
component uses those drivers directly, without a display/BSP dependency.

Pin assignments and initialization follow Espressif's
[Korvo-1 V1.1 guide](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s31/esp32-s31-korvo-1/user_guide.html),
[board configuration](https://github.com/espressif/esp-board-manager/tree/main/esp_boards/esp32_s31_korvo_1),
and [pinned ES8389 tests](https://github.com/espressif/esp-audio-dev/blob/3d22df96b33942791bfcc297e449b7bfd0c9429e/esp_codec_dev/test_apps/codec_dev_test/main/boards/esp32s31/test_board_es8389.c).
The camera has a dedicated 20 MHz LEDC XCLK on GPIO55 before SCCB detection.
Camera SCCB and codec control share I2C0 on GPIO0/1, with reference-counted
startup ownership so failure of one device does not tear down the other.

Host tests cover sender concurrency, frame lifetime, manifest formats,
cancellation, and initialization rollback. They do not establish hardware
capture quality, achieved frame rate, microphone routing, or sustained Wi-Fi
throughput. Those require validation on the board.
