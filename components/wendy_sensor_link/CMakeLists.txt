set(srcs "")
set(priv_requires wendy_core wendy_com freertos esp_timer)

# IDF scans REQUIRES before Kconfig values are available. Declare the local
# driver dependency by target; the camera dependency is conditional in the
# manifest, which the component manager resolves after loading Kconfig.
if(IDF_TARGET STREQUAL "esp32s3")
    list(APPEND priv_requires esp_driver_i2s)
endif()

if(CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3)
    list(APPEND srcs
        "src/wendy_sensor_link.c"
        "src/cam_capture.c"
        "src/cam_loop.c"
        "src/mic.c"
    )
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES ${priv_requires}
)
