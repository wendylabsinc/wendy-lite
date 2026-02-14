/**
 * Hand-assembled WASM binary: Blink demo for Wokwi simulation.
 *
 * This module imports from the "wendy" namespace:
 *   - gpio_configure(i32 pin, i32 mode, i32 pull) -> i32
 *   - gpio_write(i32 pin, i32 level) -> i32
 *   - timer_delay_ms(i32 ms)
 *
 * Behavior:
 *   1. Configure GPIO 2 and GPIO 4 as outputs
 *   2. Alternate blinking: GPIO 2 on / GPIO 4 off, then swap
 *   3. 500ms delay between toggles, 40 iterations
 *
 * Equivalent C code:
 *   void _start(void) {
 *       gpio_configure(2, 1, 0);  // output, no pull
 *       gpio_configure(4, 1, 0);
 *       for (int i = 0; i < 40; i++) {
 *           gpio_write(2, 1); gpio_write(4, 0);
 *           timer_delay_ms(500);
 *           gpio_write(2, 0); gpio_write(4, 1);
 *           timer_delay_ms(500);
 *       }
 *       gpio_write(2, 0); gpio_write(4, 0);
 *   }
 *
 * WAT (text format) equivalent:
 *   (module
 *     (import "wendy" "gpio_configure" (func $gc (param i32 i32 i32) (result i32)))
 *     (import "wendy" "gpio_write"     (func $gw (param i32 i32) (result i32)))
 *     (import "wendy" "timer_delay_ms" (func $td (param i32)))
 *     (memory (export "memory") 1)
 *     (func $start (export "_start")
 *       (local $i i32)
 *       ;; configure pins
 *       (drop (call $gc (i32.const 2) (i32.const 1) (i32.const 0)))
 *       (drop (call $gc (i32.const 4) (i32.const 1) (i32.const 0)))
 *       ;; loop
 *       (local.set $i (i32.const 0))
 *       (block $brk (loop $lp
 *         (drop (call $gw (i32.const 2) (i32.const 1)))
 *         (drop (call $gw (i32.const 4) (i32.const 0)))
 *         (call $td (i32.const 500))
 *         (drop (call $gw (i32.const 2) (i32.const 0)))
 *         (drop (call $gw (i32.const 4) (i32.const 1)))
 *         (call $td (i32.const 500))
 *         (local.set $i (i32.add (local.get $i) (i32.const 1)))
 *         (br_if $lp (i32.lt_s (local.get $i) (i32.const 40)))
 *       ))
 *       ;; turn off both
 *       (drop (call $gw (i32.const 2) (i32.const 0)))
 *       (drop (call $gw (i32.const 4) (i32.const 0)))
 *     )
 *   )
 */

#pragma once

#include <stdint.h>

static const uint8_t demo_wasm_binary[] = {
    /* ── Magic number + version ─────────────────────────── */
    0x00, 0x61, 0x73, 0x6D,  /* \0asm */
    0x01, 0x00, 0x00, 0x00,  /* version 1 */

    /* ── Type section (id=1) ────────────────────────────── */
    0x01,                    /* section id */
    0x15,                    /* section size: 21 bytes */
    0x04,                    /* 4 type entries */
    /* type 0: (i32, i32, i32) -> (i32)  [gpio_configure] */
    0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x01, 0x7F,
    /* type 1: (i32, i32) -> (i32)       [gpio_write] */
    0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
    /* type 2: (i32) -> ()               [timer_delay_ms] */
    0x60, 0x01, 0x7F, 0x00,
    /* type 3: () -> ()                  [_start] */
    0x60, 0x00, 0x00,

    /* ── Import section (id=2) ──────────────────────────── */
    0x02,                    /* section id */
    0x42,                    /* section size: 66 bytes */
    0x03,                    /* 3 imports */
    /* import 0: wendy.gpio_configure -> type 0 */
    0x05, 'w','e','n','d','y',
    0x0E, 'g','p','i','o','_','c','o','n','f','i','g','u','r','e',
    0x00, 0x00,
    /* import 1: wendy.gpio_write -> type 1 */
    0x05, 'w','e','n','d','y',
    0x0A, 'g','p','i','o','_','w','r','i','t','e',
    0x00, 0x01,
    /* import 2: wendy.timer_delay_ms -> type 2 */
    0x05, 'w','e','n','d','y',
    0x0E, 't','i','m','e','r','_','d','e','l','a','y','_','m','s',
    0x00, 0x02,

    /* ── Function section (id=3) ────────────────────────── */
    0x03,                    /* section id */
    0x02,                    /* section size: 2 bytes */
    0x01,                    /* 1 function */
    0x03,                    /* function 0 has type 3 */

    /* ── Memory section (id=5) ──────────────────────────── */
    0x05,                    /* section id */
    0x03,                    /* section size: 3 bytes */
    0x01,                    /* 1 memory */
    0x00, 0x01,              /* min=1 page (64KB), no max */

    /* ── Export section (id=7) ──────────────────────────── */
    0x07,                    /* section id */
    0x13,                    /* section size: 19 bytes */
    0x02,                    /* 2 exports */
    /* export 0: "_start" -> function index 3 */
    0x06, '_','s','t','a','r','t',
    0x00,                    /* kind: function */
    0x03,                    /* index: 3 (after 3 imports) */
    /* export 1: "memory" -> memory index 0 */
    0x06, 'm','e','m','o','r','y',
    0x02,                    /* kind: memory */
    0x00,                    /* index: 0 */

    /* ── Code section (id=10) ───────────────────────────── */
    0x0A,                    /* section id */
    0x62,                    /* section size: 98 bytes */
    0x01,                    /* 1 function body */
    0x60,                    /* body size: 96 bytes */

    /* locals: 1 group of 1 x i32 */
    0x01, 0x01, 0x7F,

    /* gpio_configure(2, 1, 0) */
    0x41, 0x02,              /* i32.const 2 */
    0x41, 0x01,              /* i32.const 1 */
    0x41, 0x00,              /* i32.const 0 */
    0x10, 0x00,              /* call 0 (gpio_configure) */
    0x1A,                    /* drop */

    /* gpio_configure(4, 1, 0) */
    0x41, 0x04,              /* i32.const 4 */
    0x41, 0x01,              /* i32.const 1 */
    0x41, 0x00,              /* i32.const 0 */
    0x10, 0x00,              /* call 0 */
    0x1A,                    /* drop */

    /* i = 0 */
    0x41, 0x00,              /* i32.const 0 */
    0x21, 0x00,              /* local.set 0 */

    /* block $brk */
    0x02, 0x40,
    /* loop $lp */
    0x03, 0x40,

    /* gpio_write(2, 1) - green LED on */
    0x41, 0x02,
    0x41, 0x01,
    0x10, 0x01,              /* call 1 (gpio_write) */
    0x1A,                    /* drop */

    /* gpio_write(4, 0) - red LED off */
    0x41, 0x04,
    0x41, 0x00,
    0x10, 0x01,
    0x1A,

    /* timer_delay_ms(500) */
    0x41, 0xF4, 0x03,        /* i32.const 500 */
    0x10, 0x02,              /* call 2 (timer_delay_ms) */

    /* gpio_write(2, 0) - green LED off */
    0x41, 0x02,
    0x41, 0x00,
    0x10, 0x01,
    0x1A,

    /* gpio_write(4, 1) - red LED on */
    0x41, 0x04,
    0x41, 0x01,
    0x10, 0x01,
    0x1A,

    /* timer_delay_ms(500) */
    0x41, 0xF4, 0x03,
    0x10, 0x02,

    /* i++ */
    0x20, 0x00,              /* local.get 0 */
    0x41, 0x01,              /* i32.const 1 */
    0x6A,                    /* i32.add */
    0x22, 0x00,              /* local.tee 0 */

    /* if i < 40, continue loop */
    0x41, 0x28,              /* i32.const 40 */
    0x48,                    /* i32.lt_s */
    0x0D, 0x00,              /* br_if 0 (loop) */

    0x0B,                    /* end loop */
    0x0B,                    /* end block */

    /* gpio_write(2, 0) - turn off green */
    0x41, 0x02,
    0x41, 0x00,
    0x10, 0x01,
    0x1A,

    /* gpio_write(4, 0) - turn off red */
    0x41, 0x04,
    0x41, 0x00,
    0x10, 0x01,
    0x1A,

    0x0B,                    /* end function */
};

static const uint32_t demo_wasm_binary_len = sizeof(demo_wasm_binary);
