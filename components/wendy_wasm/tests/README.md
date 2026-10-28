These host checks use self-contained fixtures. Point `WAMR_ROOT_DIR` at a
pristine espressif/wasm-micro-runtime 2.4.0~1 tree and `IDF_PATH` at ESP-IDF 6.0.3:

```sh
export IDF_PATH=/path/to/esp-idf
cmake -S components/wendy_wasm/tests -B /tmp/wendy-wasm-tests \
  -DWAMR_ROOT_DIR=/path/to/pristine/wasm-micro-runtime \
  -DWENDY_TEST_SANITIZE=ON
cmake --build /tmp/wendy-wasm-tests
ctest --test-dir /tmp/wendy-wasm-tests --output-on-failure
```

The admission and real WAMR memory.grow checks cover the byte ceiling and
host-managed heap insertion. The linear replacement check applies the registered
platform and mapping patches to private files, then executes the production
linear allocation/free and core lifecycle functions against the SDK's TLSF
allocator. The partition loader check executes the production loader with SDK
flash and WAMR ownership edges stubbed; it checks XIP, writable fallback, and
failure cleanup under ASAN/UBSAN.

For a complete component compile/link with SDK headers, use an empty work dir:

```sh
python3 components/wendy_wasm/tests/sdk_component_test.py \
  --idf "$IDF_PATH" --wamr /path/to/pristine/wasm-micro-runtime \
  --work-dir /tmp/wendy-sdk-c5 --target esp32c5 --profile psram
```

Also test `--target esp32c6 --profile default` and `--target esp32c6 --profile
rtc-xip`, each with its own empty work dir. The runner copies both components and
patches before building and verifies the requested Kconfig options and patched
WAMR tree. It never flashes hardware or edits the installed SDK/dependencies.
Compile/link coverage does not establish PSRAM placement, RTC performance, XIP
ABI compatibility, or flash replacement behavior on a physical board.
