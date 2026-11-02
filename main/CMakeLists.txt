set(main_sources "wendy_main.c")
if(CONFIG_WENDY_NET_TEST_SENSOR_SERVICE)
    list(APPEND main_sources "wendy_net_sensor_probe.c")
endif()
idf_component_register(
    SRCS ${main_sources}
    INCLUDE_DIRS "."
    REQUIRES wendy_core
    PRIV_REQUIRES wendy_pki wendy_net_peer wendy_sensor_link wendy_benchmark wendy_display esp_driver_tsens
)
