set(requires wasm-micro-runtime)

# TinyUSB only available on chips with USB OTG (ESP32-S2, ESP32-S3, ESP32-P4).
if(CONFIG_IDF_TARGET_ESP32S2 OR CONFIG_IDF_TARGET_ESP32S3 OR CONFIG_IDF_TARGET_ESP32P4)
    list(APPEND requires esp_tinyusb)
endif()

idf_component_register(
    SRCS "src/wendy_app_usb.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
