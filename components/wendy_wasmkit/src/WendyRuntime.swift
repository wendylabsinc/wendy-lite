// Runtime.swift — WasmKit-backed implementation of the wendy_wasm.h C API.
//
// Compiled with -enable-experimental-feature Embedded targeting riscv32-none-none-eabi.
// All public entry points use @_cdecl so they are callable from C with the
// exact names declared in wendy_wasm.h.

import WasmKit
import WasmTypes
import WendyC

// ── Global runtime state ──────────────────────────────────────────────────────
//
// Embedded Swift has no dynamic dispatch / existentials for protocol types that
// have associated types, so we keep concrete types here.

private var gEngine: Engine? = nil
private var gStore: Store? = nil
private var gConfig = WasmKitConfig()

private struct WasmKitConfig {
    var stackSize: UInt32 = 16_384
    var heapSize: UInt32  = 32_768
    var poolSize: UInt32  = 163_840
    var usePSRAM: Bool    = false
}

// ── Module handle ─────────────────────────────────────────────────────────────

// C code (wendy_main.c) uses `wendy_wasm_module_handle_t` which is a typedef
// for `struct wendy_wasm_module *`.  In the WasmKit backend we allocate an
// opaque Swift-managed object and vend its address as the opaque handle.
//
// We use a manual heap allocation via UnsafeMutablePointer so that the object's
// address is stable across borrow scopes and compatible with Embedded Swift's
// restrictions on existentials.

final class WasmModule {
    var module: Module
    var instance: Instance
    var state: wendy_wasm_state_t

    init(module: Module, instance: Instance) {
        self.module   = module
        self.instance = instance
        self.state    = WENDY_WASM_STATE_LOADED
    }
}

// We keep a global reference to the currently running module so that host
// functions can request termination via wendy_wasm_stop().
private var gCurrentModule: UnsafeMutablePointer<WasmModule?>? = nil

// We store a raw pointer to the heap-allocated WasmModule in the opaque handle.
// The caller must free it by calling wendy_wasm_unload().
private func makeHandle(_ m: WasmModule) -> wendy_wasm_module_handle_t? {
    let ptr = UnsafeMutablePointer<WasmModule>.allocate(capacity: 1)
    ptr.initialize(to: m)
    // C expects struct wendy_wasm_module*, but in the WasmKit backend
    // wendy_wasm_module is never defined — we repurpose the pointer type.
    // The cast is safe because wendy_wasm_module_handle_t is just `void *` at
    // the ABI boundary (opaque pointer).
    return OpaquePointer(ptr)
}

private func unwrapHandle(_ handle: wendy_wasm_module_handle_t?) -> UnsafeMutablePointer<WasmModule>? {
    guard let handle else { return nil }
    return unsafeBitCast(handle, to: UnsafeMutablePointer<WasmModule>.self)
}

// ── Termination flag ──────────────────────────────────────────────────────────

// Set by wendy_wasm_stop(); host functions check this to avoid calling back
// into a module that is being torn down.  `internal` (not `private`) so that
// WendyImports.swift (same module, different file) can read it.
var gTerminateRequested: Bool = false

// ── C API implementation ──────────────────────────────────────────────────────

@_cdecl("wendy_wasm_prealloc_pool")
public func wendy_wasm_prealloc_pool(_ poolSize: UInt32) -> Int32 {
    // WasmKit manages its own memory without a pre-allocated pool.
    // This is a no-op in the WasmKit backend; we just record the requested size
    // so it can be used as a hint later.
    gConfig.poolSize = poolSize
    wendy_log(ESP_LOG_INFO, "wasmkit", "pool prealloc noted; WasmKit manages memory internally")
    return ESP_OK
}

@_cdecl("wendy_wasm_init")
public func wendy_wasm_init(_ config: UnsafePointer<wendy_wasm_config_t>?) -> Int32 {
    guard gEngine == nil else {
        wendy_log(ESP_LOG_WARN, "wasmkit", "already initialized\n")
        return ESP_OK
    }
    guard let config else { return ESP_ERR_INVALID_ARG }

    gConfig.stackSize = config.pointee.stack_size
    gConfig.heapSize  = config.pointee.heap_size
    gConfig.usePSRAM  = config.pointee.use_psram

    // Store output callback
    wendy_wasmkit_set_output_cb(config.pointee.output_cb, config.pointee.output_ctx)

    let engineConfig = EngineConfiguration()
    gEngine = Engine(configuration: engineConfig)
    gStore  = Store(engine: gEngine!)

    wendy_log(ESP_LOG_INFO, "wasmkit", "WasmKit runtime initialized")
    return ESP_OK
}

@_cdecl("wendy_wasm_load")
public func wendy_wasm_load(
    _ wasmBuf: UnsafePointer<UInt8>?,
    _ wasmLen: UInt32,
    _ out: UnsafeMutablePointer<wendy_wasm_module_handle_t?>?
) -> Int32 {
    guard gEngine != nil, let store = gStore else { return ESP_ERR_INVALID_STATE }
    guard let buf = wasmBuf, wasmLen > 0, let out else { return ESP_ERR_INVALID_ARG }

    let bytes = Array(UnsafeBufferPointer(start: buf, count: Int(wasmLen)))

    let parsedModule: Module
    do throws(WasmKitError) {
        parsedModule = try parseWasm(bytes: bytes)
    } catch {
        wendy_log(ESP_LOG_ERROR, "wasmkit", "WASM parse failed\n")
        return ESP_FAIL
    }

    let instance: Instance
    do throws(WasmKitError) {
        var imports = Imports()
        buildWendyImports(store: store, into: &imports)
        instance = try parsedModule.instantiate(store: store, imports: imports)
    } catch {
        wendy_log(ESP_LOG_ERROR, "wasmkit", "WASM instantiation failed\n")
        return ESP_FAIL
    }

    let mod = WasmModule(module: parsedModule, instance: instance)
    out.pointee = makeHandle(mod)
    wendy_log(ESP_LOG_INFO, "wasmkit", "WASM module loaded")
    return ESP_OK
}

@_cdecl("wendy_wasm_load_from_partition")
public func wendy_wasm_load_from_partition(
    _ partitionLabel: UnsafePointer<CChar>?,
    _ out: UnsafeMutablePointer<wendy_wasm_module_handle_t?>?
) -> Int32 {
    guard gEngine != nil else { return ESP_ERR_INVALID_STATE }
    guard let label = partitionLabel, let out else { return ESP_ERR_INVALID_ARG }

    // Find partition (0x80 = ESPHTTPD subtype used by wasm_a, 0x81 = FAT fallback)
    var part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_DATA_ESPHTTPD,
        label)
    if part == nil {
        part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA,
            ESP_PARTITION_SUBTYPE_DATA_FAT,
            label)
    }
    guard let part else {
        wendy_log(ESP_LOG_ERROR, "wasmkit", "partition not found\n")
        return ESP_ERR_NOT_FOUND
    }

    // Read 4-byte size header
    var wasmLen: UInt32 = 0
    let err = esp_partition_read(part, 0, &wasmLen, 4)
    guard err == ESP_OK, wasmLen > 0, wasmLen <= part.pointee.size - 4 else {
        wendy_log(ESP_LOG_ERROR, "wasmkit", "invalid WASM in partition\n")
        return ESP_ERR_INVALID_SIZE
    }

    // Read the WASM binary
    var bytes = [UInt8](repeating: 0, count: Int(wasmLen))
    let readErr = esp_partition_read(part, 4, &bytes, Int(wasmLen))
    guard readErr == ESP_OK else { return readErr }

    // Reuse load path
    return bytes.withUnsafeBufferPointer { ptr in
        wendy_wasm_load(ptr.baseAddress, wasmLen, out)
    }
}

@_cdecl("wendy_wasm_run")
public func wendy_wasm_run(_ handle: wendy_wasm_module_handle_t?) -> Int32 {
    guard let ptr = unwrapHandle(handle) else { return ESP_ERR_INVALID_ARG }
    guard ptr.pointee.state == WENDY_WASM_STATE_LOADED else { return ESP_ERR_INVALID_STATE }

    gTerminateRequested = false
    ptr.pointee.state = WENDY_WASM_STATE_RUNNING
    wendy_log(ESP_LOG_INFO, "wasmkit", "executing WASM module...\n")

    // Look for _start (then main) export
    let instance = ptr.pointee.instance
    guard let startFn = instance.exports[function: "_start"]
        ?? instance.exports[function: "main"] else {
        wendy_log(ESP_LOG_ERROR, "wasmkit", "no _start or main function found\n")
        ptr.pointee.state = WENDY_WASM_STATE_ERROR
        return ESP_ERR_NOT_FOUND
    }

    do throws(Trap) {
        _ = try startFn.invoke()
    } catch {
        wendy_log(ESP_LOG_ERROR, "wasmkit", "WASM execution trapped\n")
        ptr.pointee.state = WENDY_WASM_STATE_ERROR
        return ESP_FAIL
    }

    ptr.pointee.state = WENDY_WASM_STATE_STOPPED
    wendy_log(ESP_LOG_INFO, "wasmkit", "WASM module finished\n")
    return ESP_OK
}

@_cdecl("wendy_wasm_stop")
public func wendy_wasm_stop(_ handle: wendy_wasm_module_handle_t?) -> Int32 {
    guard let ptr = unwrapHandle(handle) else { return ESP_ERR_INVALID_ARG }
    if ptr.pointee.state == WENDY_WASM_STATE_RUNNING {
        gTerminateRequested = true
        ptr.pointee.state = WENDY_WASM_STATE_STOPPED
        // WasmKit does not have a runtime_terminate() like WAMR; the stop flag
        // is checked by host functions that would re-enter the module.
        // The next time a host function yields (timer_delay_ms, sys_yield etc.)
        // it will notice gTerminateRequested and throw a Trap.
    }
    return ESP_OK
}

@_cdecl("wendy_wasm_is_terminating")
public func wendy_wasm_is_terminating() -> Bool {
    return gTerminateRequested
}

@_cdecl("wendy_wasm_unload")
public func wendy_wasm_unload(_ handle: wendy_wasm_module_handle_t?) {
    guard let ptr = unwrapHandle(handle) else { return }
    if ptr.pointee.state == WENDY_WASM_STATE_RUNNING {
        _ = wendy_wasm_stop(handle)
    }
    ptr.deinitialize(count: 1)
    ptr.deallocate()
}

@_cdecl("wendy_wasm_get_state")
public func wendy_wasm_get_state(_ handle: wendy_wasm_module_handle_t?) -> wendy_wasm_state_t {
    guard let ptr = unwrapHandle(handle) else { return WENDY_WASM_STATE_IDLE }
    return ptr.pointee.state
}

@_cdecl("wendy_wasm_get_mem_stats")
public func wendy_wasm_get_mem_stats(
    _ handle: wendy_wasm_module_handle_t?,
    _ stats: UnsafeMutablePointer<wendy_wasm_mem_stats_t>?
) -> Int32 {
    guard unwrapHandle(handle) != nil, let stats else { return ESP_ERR_INVALID_ARG }
    stats.pointee.heap_total = gConfig.heapSize
    stats.pointee.heap_used  = 0
    stats.pointee.stack_peak = 0
    return ESP_OK
}

// WAMR-specific accessors — return nil in the WasmKit backend.
// Components that call these must handle nil gracefully.

@_cdecl("wendy_wasm_get_current_module")
public func wendy_wasm_get_current_module() -> wendy_wasm_module_handle_t? { nil }

@_cdecl("wendy_wasm_get_current_exec_env")
public func wendy_wasm_get_current_exec_env() -> UnsafeMutableRawPointer? { nil }

@_cdecl("wendy_wasm_get_current_module_inst")
public func wendy_wasm_get_current_module_inst() -> UnsafeMutableRawPointer? { nil }

@_cdecl("wendy_wasm_deinit")
public func wendy_wasm_deinit() {
    gStore  = nil
    gEngine = nil
    wendy_log(ESP_LOG_INFO, "wasmkit", "WasmKit runtime destroyed\n")
}

@_cdecl("wendy_wasm_reinit")
public func wendy_wasm_reinit() -> Int32 {
    wendy_wasm_deinit()
    // Re-init is not meaningful without a config; the caller should call
    // wendy_wasm_init() again.  Return OK to avoid a crash in wendy_main.c.
    wendy_log(ESP_LOG_WARN, "wasmkit", "reinit called — call wendy_wasm_init() to reinitialise\n")
    return ESP_OK
}
