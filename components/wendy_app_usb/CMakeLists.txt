set(requires wasm-micro-runtime)

# Pull in TinyUSB only when the feature is enabled AND the SoC has USB OTG.
# (ESP32-S2/S3/P4 all have OTG; C6 does not.)
if(CONFIG_WENDY_APP_USB AND (CONFIG_IDF_TARGET_ESP32S2 OR CONFIG_IDF_TARGET_ESP32S3 OR CONFIG_IDF_TARGET_ESP32P4))
    list(APPEND requires esp_tinyusb)
endif()

idf_component_register(
    SRCS "src/wendy_app_usb.c"
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
