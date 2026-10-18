set(srcs "")
set(priv_requires wendy_core wendy_com freertos esp_timer)

# Keep the feature's Kconfig symbol visible without PSRAM so conditional
# manifest dependencies can evaluate it for the generic S31 profile.
if(CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1 AND NOT CONFIG_SPIRAM)
    message(FATAL_ERROR "Korvo-1 SensorLink requires CONFIG_SPIRAM=y.")
endif()

# IDF scans REQUIRES before Kconfig values are available. Declare the local
# driver dependency by target; the camera dependency is conditional in the
# manifest, which the component manager resolves after loading Kconfig.
if(IDF_TARGET STREQUAL "esp32s3" OR IDF_TARGET STREQUAL "esp32s31")
    list(APPEND priv_requires esp_driver_i2s)
endif()
if(IDF_TARGET STREQUAL "esp32s31")
    list(APPEND priv_requires esp_driver_i2c esp_driver_jpeg esp_driver_ledc)
endif()

if(CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3 OR CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1)
    list(APPEND srcs
        "src/wendy_sensor_link.c"
        "src/cam_loop.c"
    )
endif()
if(CONFIG_WENDY_SENSOR_LINK_XIAO_ESP32S3)
    list(APPEND srcs
        "src/cam_capture.c"
        "src/mic.c"
    )
endif()
if(CONFIG_WENDY_SENSOR_LINK_ESP32S31_KORVO_1)
    list(APPEND srcs
        "src/korvo_board.c"
        "src/korvo_camera.c"
        "src/korvo_microphone.c"
    )
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES ${priv_requires}
)
