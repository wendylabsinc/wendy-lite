idf_component_register(
    SRCS "wendy_main.c"
    INCLUDE_DIRS "."
    REQUIRES wendy_core
    PRIV_REQUIRES wendy_pki wendy_sensor_link wendy_benchmark wendy_display
)
