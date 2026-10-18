set(srcs "")
# Manifest rules must see this option even on profiles without PSRAM or SMP.
# Validate its requirements here instead of hiding the Kconfig symbol.
if(CONFIG_WENDY_KORVO_BENCHMARK AND (NOT CONFIG_SPIRAM OR CONFIG_FREERTOS_UNICORE))
    message(FATAL_ERROR "Korvo-1 benchmarks require CONFIG_SPIRAM=y and CONFIG_FREERTOS_UNICORE=n.")
endif()

if(CONFIG_WENDY_KORVO_BENCHMARK)
    list(APPEND srcs "src/wendy_benchmark.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES freertos esp_timer heap wendy_sensor_link
)
