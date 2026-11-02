"""Compile the actual WendyCom startup; readiness follows ring installation."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
source = Path(os.environ.get("WENDY_COM_SOURCE", root / "components/wendy_com/src/wendy_com.c"))
declarations = r"""
#ifndef CLOCK_CONSOLE_MOCK_H
#define CLOCK_CONSOLE_MOCK_H
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
struct wcom_app_delegate;
struct wcom_sensor_link_delegate;
struct wcom_operation { void (*func)(struct wcom_operation *); };
void wcom_cmd_set_app_delegate(const struct wcom_app_delegate *);
void wcom_cmd_set_sensor_link_delegate(const struct wcom_sensor_link_delegate *);
void wcom_stdio_init(void);
void wcom_core_init(void);
void wcom_agent_init(void);
void wcom_core_exec(struct wcom_operation *);
void wendy_pki_clock_observe_console_ready(void);
#endif
"""
harness = r"""
#include "mock.h"
void wcom_start(void);
bool wcom_is_running(void);
static unsigned phase, ready_calls, ring_records;
static bool ring_installed;
void wcom_stdio_init(void) {
    assert(phase == 0 && !ring_installed);
    ring_installed = true;
    ++phase;
}
void wendy_pki_clock_observe_console_ready(void) {
    assert(ring_installed && phase == 1 && !ready_calls);
    ++ready_calls;
    ++ring_records; /* A delivery now reaches the installed output ring. */
}
void wcom_core_init(void) { assert(phase == 1); ++phase; }
void wcom_agent_init(void) { assert(phase == 2); ++phase; }
void wcom_core_exec(struct wcom_operation *operation) {
    assert(phase == 3 && operation && operation->func);
    ++phase;
    operation->func(operation);
}
void wcom_cmd_set_app_delegate(const struct wcom_app_delegate *delegate) { (void)delegate; }
void wcom_cmd_set_sensor_link_delegate(const struct wcom_sensor_link_delegate *delegate) {
    (void)delegate;
}
int main(void) {
    assert(!wcom_is_running());
    wcom_start();
    assert(wcom_is_running() && ring_installed && phase == 4);
#if CONFIG_WENDY_PKI
    assert(ready_calls == 1 && ring_records == 1);
#else
    assert(!ready_calls && !ring_records);
#endif
    return 0;
}
"""
headers = ["wendy_com.h", "wendy_com_agent.h", "wendy_com_stdio.h", "wendy_com_link.h",
           "wendy_com_cmd.h", "wendy_pki_clock_observation.h"]
with tempfile.TemporaryDirectory() as temporary:
    work = Path(temporary)
    (work / "mock.h").write_text(declarations)
    for header in headers:
        (work / header).write_text('#include "mock.h"\n')
    (work / "harness.c").write_text(harness)
    for pki in (1, 0):
        if not pki:
            (work / "wendy_pki_clock_observation.h").unlink()
        binary = work / f"console-pki-{pki}"
        command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-parameter", "-fsanitize=address,undefined", "-I", str(work),
                   f"-DCONFIG_WENDY_PKI={pki}"]
        subprocess.run(command + [str(source), str(work / "harness.c"), "-o", str(binary)],
                       check=True)
        subprocess.run([str(binary)], check=True)
        print(f"actual wcom_start console readiness, PKI={pki}: PASS", flush=True)
