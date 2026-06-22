// WendyImports.swift — WasmKit Imports registration for all "wendy" host functions.
//
// This file builds the Imports dict that is passed to Module.instantiate().
// Every host function that the WASM app can call is defined here.
//
// WAMR type annotations mapped to WasmKit parameter types:
//   i  → .i32      I  → .i64
//   f  → .f32      F  → .f64
//   *  → .i32  (WASM linear-memory offset; must be translated via `memory`)
//   ~  → .i32  (length accompanying a `*` pointer; auto-translated by WAMR
//               but just a raw i32 in WasmKit)
//
// For functions that accept memory pointers the host function receives raw
// WASM offsets.  We validate/translate them via:
//   guard let mem = caller.instance?.exports.find(memory: "memory") else { ... }
//   mem.withUnsafeBufferPointer(offset: UInt(ptr), count: Int(len)) { raw in ... }
//   mem.withUnsafeMutableBufferPointer(offset: UInt(ptr), count: Int(len)) { raw in ... }

import WasmKit
import WasmTypes
import WendyC

// ── Helpers ───────────────────────────────────────────────────────────────────
// WasmKit stores i32 as UInt32; HAL functions use Int32 (C `int`).
// These extensions keep call-site code readable.

extension Value {
    // Create from a C int32 result (sign-preserving bit reinterpretation)
    @inline(__always)
    static func int32(_ v: Int32) -> Value { .i32(UInt32(bitPattern: v)) }
    @inline(__always)
    static func int64(_ v: Int64) -> Value { .i64(UInt64(bitPattern: v)) }
}

extension UInt32 {
    // Reinterpret WASM i32 as C int when passing to HAL functions
    @inline(__always) var cInt: Int32 { Int32(bitPattern: self) }
}

extension UInt64 {
    // Reinterpret WASM i64 as C int64 when passing to HAL functions
    @inline(__always) var cInt64: Int64 { Int64(bitPattern: self) }
}

// ── Public entry point ────────────────────────────────────────────────────────

func buildWendyImports(store: Store, into imports: inout Imports) {

    // ── Built-ins ─────────────────────────────────────────────────────────────
    registerPrint(store: store, into: &imports)
    registerEnv(store: store, into: &imports)

    // ── HAL ───────────────────────────────────────────────────────────────────
    #if CONFIG_WENDY_HAL_GPIO
    registerGPIO(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_HAL_I2C
    registerI2C(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_HAL_TIMER
    registerTimer(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_HAL_NEOPIXEL
    registerNeoPixel(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_HAL_RMT
    registerRMT(store: store, into: &imports)
    #endif

    // ── Subsystems ────────────────────────────────────────────────────────────
    #if CONFIG_WENDY_SYS
    registerSys(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_STORAGE
    registerStorage(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_UART
    registerUART(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_SPI
    registerSPI(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_OTEL
    registerOTel(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_WASI_SHIM
    registerWASI(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_BLE
    registerBLE(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_NET
    registerNet(store: store, into: &imports)
    #endif
    #if CONFIG_WENDY_APP_USB
    registerAppUSB(store: store, into: &imports)
    #endif
}

// ── Helper: dispatch pending callbacks to the WASM instance ──────────────────
//
// Called from sys_yield and sys_wait_for_event.  Returns the number of
// callbacks dispatched to the guest's wendy_handle_callback export.

private func dispatchCallbacks(instance: Instance, timeout: UInt32 = 0) -> Int32 {
    guard let handleFn = instance.exports.find(function: "wendy_handle_callback") else {
        // Guest didn't export the callback handler; drain the queue silently.
        var evt = wendy_callback_event_t(handler_id: 0, arg0: 0, arg1: 0, arg2: 0)
        while wendy_callback_dequeue(&evt, 0) {}
        return 0
    }

    var count: Int32 = 0
    var evt = wendy_callback_event_t(handler_id: 0, arg0: 0, arg1: 0, arg2: 0)

    // Wait for the first event (blocking), then drain the rest.
    let ticks: UInt32 = timeout > 0 ? UInt32(wendy_ms_to_ticks(timeout)) : 0
    if wendy_callback_dequeue(&evt, ticks) {
        if !gTerminateRequested {
            _ = try? handleFn.invoke([
                .i32(evt.handler_id),
                .i32(evt.arg0),
                .i32(evt.arg1),
                .i32(evt.arg2),
            ])
            count += 1
        }
    }

    // Drain remaining events without waiting
    while !gTerminateRequested && wendy_callback_dequeue(&evt, 0) {
        _ = try? handleFn.invoke([
            .i32(evt.handler_id),
            .i32(evt.arg0),
            .i32(evt.arg1),
            .i32(evt.arg2),
        ])
        count += 1
    }

    return count
}

// ── wendy_print ───────────────────────────────────────────────────────────────

private func registerPrint(store: Store, into imports: inout Imports) {
    // wendy_print(buf: *u8, len: i32) -> i32
    // Signature: (*~)i — buf pointer + length
    imports.define(module: "wendy", name: "wendy_print",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let wasmPtr = UInt(bitPattern: Int(args[0].i32))
            let len     = Int(args[1].i32)
            guard len > 0,
                  let mem = caller.instance?.exports.find(memory: "memory") else {
                return [.int32(-1)]
            }
            mem.withUnsafeBufferPointer(offset: wasmPtr, count: len) { raw in
                wendy_wasmkit_handle_print(
                    raw.baseAddress?.assumingMemoryBound(to: CChar.self),
                    Int32(len))
            }
            return [.int32(Int32(len))]
        }
    )
}

// ── "env" module: __stack_chk_fail, posix_memalign ───────────────────────────

private func registerEnv(store: Store, into imports: inout Imports) {
    imports.define(module: "env", name: "__stack_chk_fail",
        Function(store: store, parameters: [], results: []) { _, _ in
            wendy_log(ESP_LOG_ERROR, "wasmkit", "__stack_chk_fail: stack smashing detected\n")
            return []
        }
    )

    // posix_memalign(*pp, align, size) -> i32
    // pp is a WASM pointer to a i32 slot; we allocate from the WASM heap.
    // WasmKit does not expose wasm_runtime_module_malloc, so we use
    // a simple bump allocator via the WASM module's own heap by growing memory.
    // For now: return ENOMEM; guest apps should use stack allocation instead.
    imports.define(module: "env", name: "posix_memalign",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, _ in
            return [.int32(12)] // ENOMEM — override with a proper allocator if needed
        }
    )
}

// ── GPIO ──────────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_HAL_GPIO
private func registerGPIO(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "gpio_configure",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_gpio_configure(
                args[0].i32.cInt,
                wendy_gpio_mode_t(UInt32(args[1].i32)),
                wendy_gpio_pull_t(UInt32(args[2].i32))))]
        }
    )
    imports.define(module: "wendy", name: "gpio_read",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_gpio_read(args[0].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "gpio_write",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_gpio_write(args[0].i32.cInt, args[1].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "gpio_set_pwm",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_gpio_set_pwm(args[0].i32.cInt, UInt32(args[1].i32), UInt8(args[2].i32)))]
        }
    )
    imports.define(module: "wendy", name: "gpio_analog_read",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_gpio_analog_read(args[0].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "gpio_set_interrupt",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_gpio_set_interrupt(args[0].i32.cInt, args[1].i32.cInt, UInt32(args[2].i32)))]
        }
    )
    imports.define(module: "wendy", name: "gpio_clear_interrupt",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_gpio_clear_interrupt(args[0].i32.cInt))]
        }
    )
}
#endif

// ── I2C ───────────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_HAL_I2C
private func registerI2C(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "i2c_init",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_i2c_init(args[0].i32.cInt, args[1].i32.cInt, args[2].i32.cInt, UInt32(args[3].i32)))]
        }
    )
    // i2c_scan(bus, addrs_ptr, max) -> count
    imports.define(module: "wendy", name: "i2c_scan",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { caller, args in
            let wasmPtr = UInt(bitPattern: Int(args[1].i32))
            let max     = Int(args[2].i32)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeMutableBufferPointer(offset: wasmPtr, count: max) { raw in
                let result = wendy_hal_i2c_scan(
                    args[0].i32.cInt,
                    raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(max))
                return [Value.int32(result)]
            }
        }
    )
    // i2c_write(bus, addr, data_ptr, len) -> i32
    imports.define(module: "wendy", name: "i2c_write",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let wasmPtr = UInt(bitPattern: Int(args[2].i32))
            let len     = Int(args[3].i32)
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: wasmPtr, count: len) { raw in
                let result = wendy_hal_i2c_write(
                    args[0].i32.cInt, UInt8(args[1].i32),
                    raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(len))
                return [Value.int32(result)]
            }
        }
    )
    // i2c_read(bus, addr, buf_ptr, len) -> i32
    imports.define(module: "wendy", name: "i2c_read",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let wasmPtr = UInt(bitPattern: Int(args[2].i32))
            let len     = Int(args[3].i32)
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeMutableBufferPointer(offset: wasmPtr, count: len) { raw in
                let result = wendy_hal_i2c_read(
                    args[0].i32.cInt, UInt8(args[1].i32),
                    raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(len))
                return [Value.int32(result)]
            }
        }
    )
    // i2c_write_read(bus, addr, wr_ptr, wr_len, rd_ptr, rd_len) -> i32
    imports.define(module: "wendy", name: "i2c_write_read",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let wrPtr = UInt(bitPattern: Int(args[2].i32))
            let wrLen = Int(args[3].i32)
            let rdPtr = UInt(bitPattern: Int(args[4].i32))
            let rdLen = Int(args[5].i32)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: wrPtr, count: wrLen) { wrRaw in
                return mem.withUnsafeMutableBufferPointer(offset: rdPtr, count: rdLen) { rdRaw in
                    let result = wendy_hal_i2c_write_read(
                        args[0].i32.cInt, UInt8(args[1].i32),
                        wrRaw.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(wrLen),
                        rdRaw.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(rdLen))
                    return [Value.int32(result)]
                }
            }
        }
    )
}
#endif

// ── NeoPixel ──────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_HAL_NEOPIXEL
private func registerNeoPixel(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "neopixel_init",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_neopixel_init(args[0].i32.cInt, args[1].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "neopixel_set",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_neopixel_set(args[0].i32.cInt, args[1].i32.cInt, args[2].i32.cInt, args[3].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "neopixel_clear",
        Function(store: store, parameters: [], results: [.i32]) { _, _ in
            return [.int32(wendy_hal_neopixel_clear())]
        }
    )
}
#endif

// ── Timer ─────────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_HAL_TIMER
private func registerTimer(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "timer_delay_ms",
        Function(store: store, parameters: [.i32], results: []) { (_, args) throws(Trap) in
            wendy_hal_timer_delay_ms(UInt32(args[0].i32))
            if gTerminateRequested { throw Trap(.unreachable) }
            return []
        }
    )
    imports.define(module: "wendy", name: "timer_millis",
        Function(store: store, parameters: [], results: [.i64]) { _, _ in
            return [.i64(wendy_hal_timer_millis())]
        }
    )
    imports.define(module: "wendy", name: "timer_set_timeout",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, args in
            let ms        = UInt32(args[0].i32)
            let handlerId = UInt32(args[1].i32)
            return [.int32(wendyTimer_scheduleTimeout(ms: ms, handlerId: handlerId))]
        }
    )
    imports.define(module: "wendy", name: "timer_set_interval",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, args in
            let ms        = UInt32(args[0].i32)
            let handlerId = UInt32(args[1].i32)
            return [.int32(wendyTimer_scheduleInterval(ms: ms, handlerId: handlerId))]
        }
    )
    imports.define(module: "wendy", name: "timer_cancel",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_timer_cancel(args[0].i32.cInt))]
        }
    )
}

// Timer callbacks post via wendy_callback_post so the WASM event loop
// (sys_yield / sys_wait_for_event) can pick them up.

private func wendyTimer_scheduleTimeout(ms: UInt32, handlerId: UInt32) -> Int32 {
    // We use wendy_hal_timer_schedule with a one-shot callback that posts to
    // the callback queue with the given handler ID.
    let ctx = UnsafeMutableRawPointer(bitPattern: UInt(handlerId))
    return Int32(wendy_hal_timer_schedule(ms, { ctxPtr in
        let id = UInt32(truncatingIfNeeded: UInt(bitPattern: ctxPtr))
        _ = wendy_callback_post(id, 0, 0, 0)
    }, ctx))
}

private func wendyTimer_scheduleInterval(ms: UInt32, handlerId: UInt32) -> Int32 {
    let ctx = UnsafeMutableRawPointer(bitPattern: UInt(handlerId))
    return Int32(wendy_hal_timer_schedule_interval(ms, { ctxPtr in
        let id = UInt32(truncatingIfNeeded: UInt(bitPattern: ctxPtr))
        _ = wendy_callback_post(id, 0, 0, 0)
    }, ctx))
}
#endif

// ── RMT ───────────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_HAL_RMT
private func registerRMT(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "rmt_configure",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_rmt_configure(args[0].i32.cInt, args[1].i32.cInt))]
        }
    )
    // rmt_transmit(channel, buf_ptr, len) -> i32
    imports.define(module: "wendy", name: "rmt_transmit",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { caller, args in
            let channelId = args[0].i32.cInt
            let wasmPtr   = UInt(bitPattern: Int(args[1].i32))
            let len       = Int(args[2].i32)
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: wasmPtr, count: len) { raw in
                let result = wendy_hal_rmt_transmit(
                    channelId,
                    raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Int32(len))
                return [Value.int32(result)]
            }
        }
    )
    imports.define(module: "wendy", name: "rmt_release",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_hal_rmt_release(args[0].i32.cInt))]
        }
    )
}
#endif

// ── System ────────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_SYS
private func registerSys(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "sys_uptime_ms",
        Function(store: store, parameters: [], results: [.i64]) { _, _ in
            return [.i64(UInt64(bitPattern: esp_timer_get_time() / 1000))]
        }
    )
    imports.define(module: "wendy", name: "sys_reboot",
        Function(store: store, parameters: [], results: []) { _, _ in
            esp_restart()
            return []
        }
    )
    // sys_firmware_version(buf_ptr, buf_len) -> bytes written
    imports.define(module: "wendy", name: "sys_firmware_version",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let wasmPtr = UInt(bitPattern: Int(args[0].i32))
            let len     = Int(args[1].i32)
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeMutableBufferPointer(offset: wasmPtr, count: len) { raw in
                let written = wendy_format_version(
                    raw.baseAddress?.assumingMemoryBound(to: CChar.self),
                    Int32(len))
                return [Value.int32(written < Int32(len) ? written : Int32(len) - 1)]
            }
        }
    )
    // sys_device_id(buf_ptr, buf_len) -> bytes written
    imports.define(module: "wendy", name: "sys_device_id",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let wasmPtr = UInt(bitPattern: Int(args[0].i32))
            let len     = Int(args[1].i32)
            guard len >= 12, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeMutableBufferPointer(offset: wasmPtr, count: len) { raw in
                var mac = (UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0))
                withUnsafeMutableBytes(of: &mac) { macPtr in
                    esp_read_mac(macPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                 ESP_MAC_WIFI_STA)
                }
                let written = withUnsafeBytes(of: &mac) { macPtr in
                    wendy_format_mac(
                        raw.baseAddress?.assumingMemoryBound(to: CChar.self),
                        Int32(len),
                        macPtr.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
                return [Value.int32(written < Int32(len) ? written : Int32(len) - 1)]
            }
        }
    )
    imports.define(module: "wendy", name: "sys_sleep_ms",
        Function(store: store, parameters: [.i32], results: []) { (_, args) throws(Trap) in
            let ticks = wendy_ms_to_ticks(UInt32(args[0].i32))
            vTaskDelay(ticks > 0 ? ticks : 1)
            if gTerminateRequested { throw Trap(.unreachable) }
            return []
        }
    )
    // sys_yield() — dispatch any pending callbacks, then yield to FreeRTOS
    imports.define(module: "wendy", name: "sys_yield",
        Function(store: store, parameters: [], results: []) { (caller, _) throws(Trap) in
            if gTerminateRequested { throw Trap(.unreachable) }
            if let inst = caller.instance {
                _ = dispatchCallbacks(instance: inst, timeout: 0)
            }
            vTaskDelay(1)
            if gTerminateRequested { throw Trap(.unreachable) }
            return []
        }
    )
    // sys_wait_for_event(timeout_ms) -> dispatched count
    imports.define(module: "wendy", name: "sys_wait_for_event",
        Function(store: store, parameters: [.i32], results: [.i32]) { (caller, args) throws(Trap) in
            if gTerminateRequested { throw Trap(.unreachable) }
            let timeoutMs = UInt32(args[0].i32 > 0 ? args[0].i32 : 0)
            var count: Int32 = 0
            if let inst = caller.instance {
                count = dispatchCallbacks(instance: inst, timeout: timeoutMs)
            } else if timeoutMs > 0 {
                vTaskDelay(wendy_ms_to_ticks(timeoutMs))
            }
            vTaskDelay(1)
            if gTerminateRequested { throw Trap(.unreachable) }
            return [.int32(count)]
        }
    )
}
#endif

// ── Storage ───────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_STORAGE
private func registerStorage(store: Store, into imports: inout Imports) {
    // storage_get(key_ptr, key_len, val_ptr, val_len) -> i32
    imports.define(module: "wendy", name: "storage_get",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let keyPtr = UInt(bitPattern: Int(args[0].i32)); let keyLen = Int(args[1].i32)
            let valPtr = UInt(bitPattern: Int(args[2].i32)); let valLen = Int(args[3].i32)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: keyPtr, count: keyLen) { keyRaw in
                return mem.withUnsafeMutableBufferPointer(offset: valPtr, count: valLen) { valRaw in
                    let keyStr = keyRaw.baseAddress?.assumingMemoryBound(to: CChar.self)
                    let valBuf = valRaw.baseAddress?.assumingMemoryBound(to: CChar.self)
                    return [Value.int32(wendy_storage_guest_get(keyStr, Int32(keyLen), valBuf, Int32(valLen)))]
                }
            }
        }
    )
    // storage_set(key_ptr, key_len, val_ptr, val_len) -> i32
    imports.define(module: "wendy", name: "storage_set",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let keyPtr = UInt(bitPattern: Int(args[0].i32)); let keyLen = Int(args[1].i32)
            let valPtr = UInt(bitPattern: Int(args[2].i32)); let valLen = Int(args[3].i32)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: keyPtr, count: keyLen) { keyRaw in
                return mem.withUnsafeBufferPointer(offset: valPtr, count: valLen) { valRaw in
                    let keyStr = keyRaw.baseAddress?.assumingMemoryBound(to: CChar.self)
                    let valStr = valRaw.baseAddress?.assumingMemoryBound(to: CChar.self)
                    return [Value.int32(wendy_storage_guest_set(keyStr, Int32(keyLen), valStr, Int32(valLen)))]
                }
            }
        }
    )
    // storage_delete(key_ptr, key_len) -> i32
    imports.define(module: "wendy", name: "storage_delete",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let keyPtr = UInt(bitPattern: Int(args[0].i32)); let keyLen = Int(args[1].i32)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: keyPtr, count: keyLen) { keyRaw in
                let keyStr = keyRaw.baseAddress?.assumingMemoryBound(to: CChar.self)
                return [Value.int32(wendy_storage_guest_delete(keyStr, Int32(keyLen)))]
            }
        }
    )
    // storage_exists(key_ptr, key_len) -> i32
    imports.define(module: "wendy", name: "storage_exists",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let keyPtr = UInt(bitPattern: Int(args[0].i32)); let keyLen = Int(args[1].i32)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: keyPtr, count: keyLen) { keyRaw in
                let keyStr = keyRaw.baseAddress?.assumingMemoryBound(to: CChar.self)
                return [Value.int32(wendy_storage_guest_exists(keyStr, Int32(keyLen)))]
            }
        }
    )
}
#endif

// ── UART ──────────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_UART
private func registerUART(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "uart_open",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_uart_guest_open(args[0].i32.cInt, args[1].i32.cInt, args[2].i32.cInt, args[3].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "uart_close",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_uart_guest_close(args[0].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "uart_write",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { caller, args in
            let port    = args[0].i32.cInt
            let wasmPtr = UInt(bitPattern: Int(args[1].i32))
            let len     = Int(args[2].i32)
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: wasmPtr, count: len) { raw in
                return [Value.int32(wendy_uart_guest_write(port,
                    raw.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(len)))]
            }
        }
    )
    imports.define(module: "wendy", name: "uart_read",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { caller, args in
            let port    = args[0].i32.cInt
            let wasmPtr = UInt(bitPattern: Int(args[1].i32))
            let len     = Int(args[2].i32)
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeMutableBufferPointer(offset: wasmPtr, count: len) { raw in
                return [Value.int32(wendy_uart_guest_read(port,
                    raw.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(len)))]
            }
        }
    )
    imports.define(module: "wendy", name: "uart_available",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_uart_guest_available(args[0].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "uart_flush",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_uart_guest_flush(args[0].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "uart_set_on_receive",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_uart_guest_set_on_receive(args[0].i32.cInt, UInt32(args[1].i32)))]
        }
    )
}
#endif

// ── SPI ───────────────────────────────────────────────────────────────────────

#if CONFIG_WENDY_SPI
private func registerSPI(store: Store, into imports: inout Imports) {
    imports.define(module: "wendy", name: "spi_open",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_spi_guest_open(args[0].i32.cInt, args[1].i32.cInt, args[2].i32.cInt,
                                               args[3].i32.cInt, args[4].i32.cInt, args[5].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "spi_close",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_spi_guest_close(args[0].i32.cInt))]
        }
    )
    // spi_transfer(handle, len, tx_ptr, rx_ptr) -> i32
    imports.define(module: "wendy", name: "spi_transfer",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let handle  = args[0].i32.cInt
            let len     = Int(args[1].i32)
            let txPtr   = UInt(bitPattern: Int(args[2].i32))
            let rxPtr   = UInt(bitPattern: Int(args[3].i32))
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: txPtr, count: len) { txRaw in
                return mem.withUnsafeMutableBufferPointer(offset: rxPtr, count: len) { rxRaw in
                    return [Value.int32(wendy_spi_guest_transfer(
                        handle, Int32(len),
                        txRaw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        rxRaw.baseAddress?.assumingMemoryBound(to: UInt8.self)))]
                }
            }
        }
    )
}
#endif

// ── OpenTelemetry ─────────────────────────────────────────────────────────────

#if CONFIG_WENDY_OTEL
private func registerOTel(store: Store, into imports: inout Imports) {
    // otel_log(level, msg_ptr, msg_len) -> i32
    imports.define(module: "wendy", name: "otel_log",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { caller, args in
            let level   = args[0].i32.cInt
            let wasmPtr = UInt(bitPattern: Int(args[1].i32))
            let len     = Int(args[2].i32)
            guard len > 0, let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: wasmPtr, count: len) { raw in
                return [Value.int32(wendy_otel_guest_log(level,
                    raw.baseAddress?.assumingMemoryBound(to: CChar.self), Int32(len)))]
            }
        }
    )
    // otel_metric_counter_add(name_ptr, name_len, delta: f64) -> i32
    imports.define(module: "wendy", name: "otel_metric_counter_add",
        Function(store: store, parameters: [.i32, .i32, .f64], results: [.i32]) { caller, args in
            let namePtr = UInt(bitPattern: Int(args[0].i32))
            let nameLen = Int(args[1].i32)
            let delta   = Double(bitPattern: args[2].f64)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: namePtr, count: nameLen) { raw in
                return [Value.int32(wendy_otel_guest_counter_add(
                    raw.baseAddress?.assumingMemoryBound(to: CChar.self), Int32(nameLen), delta))]
            }
        }
    )
    // otel_span_start(name_ptr, name_len) -> span_id
    imports.define(module: "wendy", name: "otel_span_start",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let namePtr = UInt(bitPattern: Int(args[0].i32))
            let nameLen = Int(args[1].i32)
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(-1)] }
            return mem.withUnsafeBufferPointer(offset: namePtr, count: nameLen) { raw in
                return [Value.int32(wendy_otel_guest_span_start(
                    raw.baseAddress?.assumingMemoryBound(to: CChar.self), Int32(nameLen)))]
            }
        }
    )
    imports.define(module: "wendy", name: "otel_span_set_status",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, args in
            return [.int32(wendy_otel_guest_span_set_status(args[0].i32.cInt, args[1].i32.cInt))]
        }
    )
    imports.define(module: "wendy", name: "otel_span_end",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, args in
            return [.int32(wendy_otel_guest_span_end(args[0].i32.cInt))]
        }
    )
}
#endif

// ── WASI Preview 1 ───────────────────────────────────────────────────────────
//
// Full WASI snapshot_preview1 surface implemented in Swift via WasmKit's Imports
// API.  No dependency on the WAMR-era wendy_wasi_shim C component.
//
// What works on embedded:
//   fd_write (stdout/stderr), random_get (esp_fill_random), clock_time_get
//   (esp_timer monotonic), clock_res_get, proc_exit, sched_yield,
//   environ/args (empty), fd_fdstat_get (char-device for stdio 0-2).
// Everything else returns ENOSYS / EBADF / ENOTSUP — no filesystem or sockets.

#if CONFIG_WENDY_WASI_SHIM
private func registerWASI(store: Store, into imports: inout Imports) {
    let m = "wasi_snapshot_preview1"

    let ok:      Int32 = 0
    let ebadf:   Int32 = 8
    let einval:  Int32 = 28
    let enosys:  Int32 = 52
    let enotsup: Int32 = 58

    // ── fd_write(fd, iovs, iovs_len, nwritten) -> errno ──────────────────────
    // Supports stdout (1) and stderr (2) only.
    imports.define(module: m, name: "fd_write",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let fd = args[0].i32.cInt
            guard fd == 1 || fd == 2 else { return [.int32(ebadf)] }
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(einval)] }
            let iovsOff = UInt(args[1].i32)
            let iovsLen = Int(args[2].i32)
            let nwrittenOff = UInt(args[3].i32)
            var total: UInt32 = 0
            if iovsLen > 0 {
                mem.withUnsafeBufferPointer(offset: iovsOff, count: iovsLen * 8) { iovRaw in
                    let base = iovRaw.baseAddress!.assumingMemoryBound(to: UInt32.self)
                    for i in 0..<iovsLen {
                        let bufOff = UInt(base[i * 2])
                        let bufLen = Int(base[i * 2 + 1])
                        guard bufLen > 0 else { continue }
                        mem.withUnsafeBufferPointer(offset: bufOff, count: bufLen) { buf in
                            wendy_wasmkit_handle_print(
                                buf.baseAddress?.assumingMemoryBound(to: CChar.self),
                                Int32(bufLen))
                            total += UInt32(bufLen)
                        }
                    }
                }
            }
            return mem.withUnsafeMutableBufferPointer(offset: nwrittenOff, count: 4) { raw in
                raw.baseAddress!.assumingMemoryBound(to: UInt32.self).pointee = total
                return [Value.int32(ok)]
            }
        }
    )

    // ── fd_read(fd, iovs, iovs_len, nread) -> errno  [stdin not supported] ──
    imports.define(module: m, name: "fd_read",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { caller, args in
            let nreadOff = UInt(args[3].i32)
            if let mem = caller.instance?.exports.find(memory: "memory") {
                mem.withUnsafeMutableBufferPointer(offset: nreadOff, count: 4) { raw in
                    raw.baseAddress!.assumingMemoryBound(to: UInt32.self).pointee = 0
                }
            }
            return [.int32(enosys)]
        }
    )

    // ── fd_close(fd) -> errno ─────────────────────────────────────────────────
    imports.define(module: m, name: "fd_close",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_seek(fd, offset: i64, whence, newoffset) -> errno ─────────────────
    imports.define(module: m, name: "fd_seek",
        Function(store: store, parameters: [.i32, .i64, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_tell(fd, newoffset) -> errno ───────────────────────────────────────
    imports.define(module: m, name: "fd_tell",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_fdstat_get(fd, stat) -> errno ──────────────────────────────────────
    // fdstat layout: filetype(u8) + pad(u8+u16) + fs_rights_base(u64) + fs_rights_inheriting(u64) = 24 bytes
    imports.define(module: m, name: "fd_fdstat_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let fd = args[0].i32.cInt
            guard fd == 0 || fd == 1 || fd == 2 else { return [.int32(ebadf)] }
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(einval)] }
            return mem.withUnsafeMutableBufferPointer(offset: UInt(args[1].i32), count: 24) { raw in
                let base = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                for i in 0..<24 { base[i] = 0 }
                base[0] = 2  // WASI_FILETYPE_CHARACTER_DEVICE
                return [Value.int32(ok)]
            }
        }
    )

    // ── fd_fdstat_set_flags(fd, flags) -> errno ───────────────────────────────
    imports.define(module: m, name: "fd_fdstat_set_flags",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_fdstat_set_rights(fd, rights_base: i64, rights_inh: i64) -> errno ─
    imports.define(module: m, name: "fd_fdstat_set_rights",
        Function(store: store, parameters: [.i32, .i64, .i64], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_prestat_get(fd, buf) -> errno ──────────────────────────────────────
    imports.define(module: m, name: "fd_prestat_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(ebadf)] })

    // ── fd_prestat_dir_name(fd, path, path_len) -> errno ─────────────────────
    imports.define(module: m, name: "fd_prestat_dir_name",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(ebadf)] })

    // ── fd_pread(fd, iovs, iovs_len, offset: i64, nread) -> errno ────────────
    imports.define(module: m, name: "fd_pread",
        Function(store: store, parameters: [.i32, .i32, .i32, .i64, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_pwrite(fd, iovs, iovs_len, offset: i64, nwritten) -> errno ────────
    imports.define(module: m, name: "fd_pwrite",
        Function(store: store, parameters: [.i32, .i32, .i32, .i64, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_sync(fd) -> errno ──────────────────────────────────────────────────
    imports.define(module: m, name: "fd_sync",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_datasync(fd) -> errno ──────────────────────────────────────────────
    imports.define(module: m, name: "fd_datasync",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_advise(fd, offset: i64, len: i64, advice) -> errno ────────────────
    imports.define(module: m, name: "fd_advise",
        Function(store: store, parameters: [.i32, .i64, .i64, .i32], results: [.i32]) { _, _ in [.int32(enotsup)] })

    // ── fd_allocate(fd, offset: i64, len: i64) -> errno ──────────────────────
    imports.define(module: m, name: "fd_allocate",
        Function(store: store, parameters: [.i32, .i64, .i64], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_filestat_get(fd, buf) -> errno ─────────────────────────────────────
    imports.define(module: m, name: "fd_filestat_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_filestat_set_size(fd, size: i64) -> errno ──────────────────────────
    imports.define(module: m, name: "fd_filestat_set_size",
        Function(store: store, parameters: [.i32, .i64], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_filestat_set_times(fd, atim: i64, mtim: i64, fst_flags) -> errno ──
    imports.define(module: m, name: "fd_filestat_set_times",
        Function(store: store, parameters: [.i32, .i64, .i64, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_readdir(fd, buf, buf_len, cookie: i64, bufused) -> errno ───────────
    imports.define(module: m, name: "fd_readdir",
        Function(store: store, parameters: [.i32, .i32, .i32, .i64, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── fd_renumber(fd, to) -> errno ──────────────────────────────────────────
    imports.define(module: m, name: "fd_renumber",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_open(fd, dirflags, path, path_len, oflags, rights_base: i64, rights_inh: i64, fdflags, opened_fd) -> errno ──
    imports.define(module: m, name: "path_open",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32, .i64, .i64, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_create_directory(fd, path, path_len) -> errno ───────────────────
    imports.define(module: m, name: "path_create_directory",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_remove_directory(fd, path, path_len) -> errno ───────────────────
    imports.define(module: m, name: "path_remove_directory",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_unlink_file(fd, path, path_len) -> errno ─────────────────────────
    imports.define(module: m, name: "path_unlink_file",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_rename(fd, old_path, old_path_len, new_fd, new_path, new_path_len) -> errno ──
    imports.define(module: m, name: "path_rename",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_link(old_fd, old_flags, old_path, old_path_len, new_fd, new_path, new_path_len) -> errno ──
    imports.define(module: m, name: "path_link",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_symlink(old_path, old_path_len, fd, new_path, new_path_len) -> errno ──
    imports.define(module: m, name: "path_symlink",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_readlink(fd, path, path_len, buf, buf_len, bufused) -> errno ─────
    imports.define(module: m, name: "path_readlink",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_filestat_get(fd, flags, path, path_len, buf) -> errno ────────────
    imports.define(module: m, name: "path_filestat_get",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── path_filestat_set_times(fd, flags, path, path_len, atim: i64, mtim: i64, fst_flags) -> errno ──
    imports.define(module: m, name: "path_filestat_set_times",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i64, .i64, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── poll_oneoff(in, out, nsubscriptions, nevents) -> errno ───────────────
    imports.define(module: m, name: "poll_oneoff",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── proc_exit(code) — terminates WASM module ──────────────────────────────
    imports.define(module: m, name: "proc_exit",
        Function(store: store, parameters: [.i32], results: []) { _, _ in
            gTerminateRequested = true
            return []
        }
    )

    // ── proc_raise(sig) -> errno ──────────────────────────────────────────────
    imports.define(module: m, name: "proc_raise",
        Function(store: store, parameters: [.i32], results: [.i32]) { _, _ in [.int32(enosys)] })

    // ── random_get(buf, buf_len) -> errno ─────────────────────────────────────
    imports.define(module: m, name: "random_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            let bufOff = UInt(args[0].i32)
            let bufLen = Int(args[1].i32)
            guard bufLen > 0 else { return [.int32(ok)] }
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(einval)] }
            return mem.withUnsafeMutableBufferPointer(offset: bufOff, count: bufLen) { raw in
                esp_fill_random(raw.baseAddress, bufLen)
                return [Value.int32(ok)]
            }
        }
    )

    // ── clock_res_get(id, resolution) -> errno ────────────────────────────────
    // Reports 1 µs (1000 ns) resolution — the esp_timer tick granularity.
    imports.define(module: m, name: "clock_res_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(einval)] }
            return mem.withUnsafeMutableBufferPointer(offset: UInt(args[1].i32), count: 8) { raw in
                raw.baseAddress!.assumingMemoryBound(to: UInt64.self).pointee = 1_000
                return [Value.int32(ok)]
            }
        }
    )

    // ── clock_time_get(id, precision: i64, time) -> errno ────────────────────
    // No real RTC; all clock IDs return monotonic µs-since-boot converted to ns.
    imports.define(module: m, name: "clock_time_get",
        Function(store: store, parameters: [.i32, .i64, .i32], results: [.i32]) { caller, args in
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(einval)] }
            let ns = esp_timer_get_time() &* 1000  // µs → ns
            return mem.withUnsafeMutableBufferPointer(offset: UInt(args[2].i32), count: 8) { raw in
                raw.baseAddress!.assumingMemoryBound(to: Int64.self).pointee = ns
                return [Value.int32(ok)]
            }
        }
    )

    // ── environ_sizes_get(count, buf_size) -> errno  [no environment] ─────────
    imports.define(module: m, name: "environ_sizes_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(einval)] }
            mem.withUnsafeMutableBufferPointer(offset: UInt(args[0].i32), count: 4) { raw in
                raw.baseAddress!.assumingMemoryBound(to: UInt32.self).pointee = 0
            }
            return mem.withUnsafeMutableBufferPointer(offset: UInt(args[1].i32), count: 4) { raw in
                raw.baseAddress!.assumingMemoryBound(to: UInt32.self).pointee = 0
                return [Value.int32(ok)]
            }
        }
    )

    // ── environ_get(environ, environ_buf) -> errno  [no environment] ──────────
    imports.define(module: m, name: "environ_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(ok)] })

    // ── args_sizes_get(argc, argv_buf_size) -> errno  [no args] ──────────────
    imports.define(module: m, name: "args_sizes_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            guard let mem = caller.instance?.exports.find(memory: "memory") else { return [.int32(einval)] }
            mem.withUnsafeMutableBufferPointer(offset: UInt(args[0].i32), count: 4) { raw in
                raw.baseAddress!.assumingMemoryBound(to: UInt32.self).pointee = 0
            }
            return mem.withUnsafeMutableBufferPointer(offset: UInt(args[1].i32), count: 4) { raw in
                raw.baseAddress!.assumingMemoryBound(to: UInt32.self).pointee = 0
                return [Value.int32(ok)]
            }
        }
    )

    // ── args_get(argv, argv_buf) -> errno  [no args] ──────────────────────────
    imports.define(module: m, name: "args_get",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(ok)] })

    // ── sched_yield() -> errno ────────────────────────────────────────────────
    imports.define(module: m, name: "sched_yield",
        Function(store: store, parameters: [], results: [.i32]) { _, _ in
            vTaskDelay(1)
            return [.int32(ok)]
        }
    )

    // ── sock_accept(fd, flags, result_fd) -> errno ────────────────────────────
    imports.define(module: m, name: "sock_accept",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enotsup)] })

    // ── sock_recv(fd, ri_data, ri_data_len, ri_flags, ro_datalen, ro_flags) -> errno ──
    imports.define(module: m, name: "sock_recv",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enotsup)] })

    // ── sock_send(fd, si_data, si_data_len, si_flags, so_datalen) -> errno ───
    imports.define(module: m, name: "sock_send",
        Function(store: store, parameters: [.i32, .i32, .i32, .i32, .i32], results: [.i32]) { _, _ in [.int32(enotsup)] })

    // ── sock_shutdown(fd, how) -> errno ───────────────────────────────────────
    imports.define(module: m, name: "sock_shutdown",
        Function(store: store, parameters: [.i32, .i32], results: [.i32]) { _, _ in [.int32(enotsup)] })
}
#endif

// ── BLE (stub — full implementation requires wendy_ble.h) ───────────────────

#if CONFIG_WENDY_BLE
private func registerBLE(store: Store, into imports: inout Imports) {
    let noopI: Function.Implementation = { _, _ in return [.int32(-1)] }
    let noop:  Function.Implementation = { _, _ in return [] }
    for (name, params, results, impl) in [
        ("ble_init",            [ValueType]([]),                   [ValueType]([.i32]), noopI),
        ("ble_advertise_start", [.i32, .i32],                      [.i32],              noopI),
        ("ble_advertise_stop",  [],                                [.i32],              noopI),
        ("ble_scan_start",      [.i32, .i32],                      [.i32],              noopI),
        ("ble_scan_stop",       [],                                [.i32],              noopI),
    ] as [(String, [ValueType], [ValueType], Function.Implementation)] {
        imports.define(module: "wendy", name: name,
            Function(store: store, parameters: params, results: results, body: impl))
    }
    _ = noop // suppress unused warning
}
#endif

// ── Net (stub — full implementation requires wendy_net.h) ────────────────────

#if CONFIG_WENDY_NET
private func registerNet(store: Store, into imports: inout Imports) {
    let noopI: Function.Implementation = { _, _ in return [.int32(-1)] }
    for (name, params) in [
        ("net_socket",  [ValueType]([.i32, .i32, .i32])),
        ("net_connect", [.i32, .i32, .i32, .i32]),
        ("net_bind",    [.i32, .i32]),
        ("net_listen",  [.i32, .i32]),
        ("net_accept",  [.i32]),
        ("net_send",    [.i32, .i32, .i32]),
        ("net_recv",    [.i32, .i32, .i32]),
        ("net_close",   [.i32]),
    ] as [(String, [ValueType])] {
        imports.define(module: "wendy", name: name,
            Function(store: store, parameters: params, results: [.i32], body: noopI))
    }
}
#endif

// ── App USB (stub) ────────────────────────────────────────────────────────────

#if CONFIG_WENDY_APP_USB
private func registerAppUSB(store: Store, into imports: inout Imports) {
    let noopI: Function.Implementation = { _, _ in return [.int32(0)] }
    for name in ["usb_cdc_write", "usb_cdc_read"] {
        imports.define(module: "wendy", name: name,
            Function(store: store, parameters: [.i32, .i32], results: [.i32], body: noopI))
    }
    imports.define(module: "wendy", name: "usb_hid_send_report",
        Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32], body: noopI))
}
#endif
