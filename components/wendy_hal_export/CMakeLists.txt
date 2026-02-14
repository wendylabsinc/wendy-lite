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

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES wendy_hal wasm-micro-runtime
)
