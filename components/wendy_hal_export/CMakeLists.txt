set(srcs "src/wendy_hal_export.c")

if(CONFIG_WENDY_HAL_GPIO)
    list(APPEND srcs "src/wendy_hal_export_gpio.c")
endif()

if(CONFIG_WENDY_HAL_I2C)
    list(APPEND srcs "src/wendy_hal_export_i2c.c")
endif()

if(CONFIG_WENDY_HAL_TIMER)
    list(APPEND srcs "src/wendy_hal_export_timer.c")
endif()

if(CONFIG_WENDY_HAL_NEOPIXEL)
    list(APPEND srcs "src/wendy_hal_export_neopixel.c")
endif()

if(CONFIG_WENDY_HAL_RMT)
    list(APPEND srcs "src/wendy_hal_export_rmt.c")
endif()

# jo/wasmkit-runtime: wasm-micro-runtime removed; wendy_hal_export_init() is a
# no-op on this branch — host functions are registered by wendy_wasmkit instead.
set(requires
    wendy_hal
    wendy_wasmkit          # provides stub wasm_export.h
    wendy_callback
    wendy_sys
    wendy_storage
    wendy_uart
    wendy_spi
    wendy_otel
    wendy_wasi_shim
    wendy_ble
    wendy_net
    wendy_app_usb
)

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
