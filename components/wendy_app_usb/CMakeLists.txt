set(requires wasm-micro-runtime)

# TinyUSB only available on chips with USB OTG (ESP32-S2, ESP32-S3)
if(CONFIG_IDF_TARGET_ESP32S2 OR CONFIG_IDF_TARGET_ESP32S3)
    list(APPEND requires esp_tinyusb)
endif()

idf_component_register(
    SRCS "src/wendy_app_usb.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
