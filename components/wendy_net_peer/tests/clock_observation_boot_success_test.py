"""Compile the actual app entry point; boot capture must precede initialization."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = Path(os.environ.get("WENDY_MAIN_SOURCE", root / "main/wendy_main.c"))
declarations = r"""
#ifndef CLOCK_BOOT_MOCK_H
#define CLOCK_BOOT_MOCK_H
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERROR_CHECK(value) do { assert((value) == ESP_OK); } while (0)
#define ESP_LOGW(...) ((void)0)
void wendy_pki_clock_observe_boot(void);
int wendy_pki_memory_init(void);
int wendy_pki_crypto_init(void);
void wendy_net_sensor_probe_init(void);
esp_err_t wendy_sensor_link_init(void);
esp_err_t wendy_net_peer_boot_radios(bool *, bool *);
esp_err_t wendy_core_set_boot_radios(bool, bool);
esp_err_t wendy_core_init(void);
void wendy_ble_power_init(void);
esp_err_t wendy_net_peer_start(void);
esp_err_t wendy_display_start(void);
esp_err_t wendy_benchmark_start(void);
const char *esp_err_to_name(esp_err_t);
#endif
"""
harness = r"""
#include "mock.h"
void app_main(void);
static unsigned phase, boot_calls;
static int64_t fake_utc = 1000, captured_utc;
static int initialized(void) { ++phase; fake_utc += 100; return ESP_OK; }
void wendy_pki_clock_observe_boot(void) {
    assert(phase == 0 && !boot_calls);
    captured_utc = fake_utc;
    ++boot_calls;
}
int wendy_pki_memory_init(void) { return initialized(); }
int wendy_pki_crypto_init(void) { return initialized(); }
void wendy_net_sensor_probe_init(void) { (void)initialized(); }
esp_err_t wendy_sensor_link_init(void) { return initialized(); }
esp_err_t wendy_net_peer_boot_radios(bool *ble, bool *wifi) {
    *ble = true; *wifi = false; return initialized();
}
esp_err_t wendy_core_set_boot_radios(bool ble, bool wifi) {
    assert(ble && !wifi); return initialized();
}
esp_err_t wendy_core_init(void) { return initialized(); }
void wendy_ble_power_init(void) { (void)initialized(); }
esp_err_t wendy_net_peer_start(void) { return initialized(); }
esp_err_t wendy_display_start(void) { return initialized(); }
esp_err_t wendy_benchmark_start(void) { return initialized(); }
const char *esp_err_to_name(esp_err_t error) { (void)error; return "mock"; }
int main(void) {
    app_main();
    assert(phase == 11 && fake_utc == 2100);
#if CONFIG_WENDY_PKI
    assert(boot_calls == 1 && captured_utc == 1000 && captured_utc != fake_utc);
#else
    assert(!boot_calls && !captured_utc);
#endif
    return 0;
}
"""
flags = ["CONFIG_WENDY_BLE", "CONFIG_WENDY_NET_PEER", "CONFIG_WENDY_NET_TEST_SENSOR_SERVICE",
         "CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3", "CONFIG_WENDY_NET_SELECT_RADIO_AT_BOOT",
         "CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1", "CONFIG_WENDY_KORVO_BENCHMARK"]
headers = ["wendy_core.h", "wendy_pki_crypto.h", "wendy_pki_clock_observation.h", "esp_log.h",
           "wendy_ble.h", "wendy_net_peer.h", "wendy_sensor_link.h", "wendy_display.h",
           "wendy_benchmark.h"]
with tempfile.TemporaryDirectory() as temporary:
    work = Path(temporary)
    (work / "mock.h").write_text(declarations)
    for header in headers:
        (work / header).write_text('#include "mock.h"\n')
    (work / "harness.c").write_text(harness)
    for pki in (1, 0):
        if not pki:
            (work / "wendy_pki_clock_observation.h").unlink()
        binary = work / f"boot-pki-{pki}"
        command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-fsanitize=address,undefined", "-I", str(work), f"-DCONFIG_WENDY_PKI={pki}"]
        command += [f"-D{flag}=1" for flag in flags]
        subprocess.run(command + [str(source), str(work / "harness.c"), "-o", str(binary)],
                       check=True)
        subprocess.run([str(binary)], check=True)
        print(f"actual app_main boot capture, PKI={pki}: PASS", flush=True)
