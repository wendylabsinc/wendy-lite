;; Wendy MCU — WAT (WebAssembly Text) NeoPixel RGB Demo
;;
;; Cycles the onboard WS2812 RGB LED (GPIO 8) through colors.
;;
;; Build with:
;;   wat2wasm blink.wat -o wat_blink.wasm
;;
;; Signatures include extra ctx/err i32 params for Swift Embedded compatibility.

(module
  ;; --- Wendy HAL imports ---

  (import "wendy" "neopixel_init"
    (func $neopixel_init (param i32 i32 i32 i32) (result i32)))

  (import "wendy" "neopixel_set"
    (func $neopixel_set (param i32 i32 i32 i32 i32 i32) (result i32)))

  (import "wendy" "neopixel_clear"
    (func $neopixel_clear (param i32 i32) (result i32)))

  (import "wendy" "timer_delay_ms"
    (func $timer_delay_ms (param i32 i32 i32)))

  ;; --- Linear memory (required by WAMR) ---

  (memory (export "memory") 1)

  ;; --- Application entry point ---

  (func (export "_start")
    (local $i i32)

    ;; Initialize NeoPixel on GPIO 8, 1 LED
    (drop (call $neopixel_init
      (i32.const 8) (i32.const 1)
      (i32.const 0) (i32.const 0)))

    ;; Cycle through colors 10 times
    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (i32.const 10)))

        ;; Red
        (drop (call $neopixel_set
          (i32.const 0) (i32.const 255) (i32.const 0) (i32.const 0)
          (i32.const 0) (i32.const 0)))
        (call $timer_delay_ms
          (i32.const 500) (i32.const 0) (i32.const 0))

        ;; Green
        (drop (call $neopixel_set
          (i32.const 0) (i32.const 0) (i32.const 255) (i32.const 0)
          (i32.const 0) (i32.const 0)))
        (call $timer_delay_ms
          (i32.const 500) (i32.const 0) (i32.const 0))

        ;; Blue
        (drop (call $neopixel_set
          (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 255)
          (i32.const 0) (i32.const 0)))
        (call $timer_delay_ms
          (i32.const 500) (i32.const 0) (i32.const 0))

        ;; i++
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )

    ;; Clear LED
    (drop (call $neopixel_clear (i32.const 0) (i32.const 0)))
  )
)
