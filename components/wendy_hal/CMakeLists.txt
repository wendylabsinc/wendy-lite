set(srcs "")

if(CONFIG_WENDY_HAL_GPIO)
    list(APPEND srcs "src/wendy_hal_gpio.c")
endif()

if(CONFIG_WENDY_HAL_I2C)
    list(APPEND srcs "src/wendy_hal_i2c.c")
endif()

if(CONFIG_WENDY_HAL_TIMER)
    list(APPEND srcs "src/wendy_hal_timer.c")
endif()

if(CONFIG_WENDY_HAL_NEOPIXEL)
    list(APPEND srcs "src/wendy_hal_neopixel.c")
endif()

# Ensure at least one source file
if(NOT srcs)
    # Create a dummy source if nothing is enabled
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_hal_stub.c" "/* no HAL modules enabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_hal_stub.c")
endif()

set(requires driver esp_timer led_strip esp_adc wendy_callback)

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
