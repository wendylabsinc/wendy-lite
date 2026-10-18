set(srcs "")
set(priv_requires "")

# IDF discovers dependencies before Kconfig values are available. Keep the
# target-specific LCD dependency off chips without an RGB display peripheral.
if(IDF_TARGET STREQUAL "esp32s31")
    list(APPEND priv_requires esp_lcd esp_timer freertos heap wendy_wifi)
endif()

if(CONFIG_WENDY_DISPLAY_ESP32S31_KORVO_1)
    list(APPEND srcs "src/wendy_display.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES ${priv_requires}
)
