idf_component_register(SRCS "main.c" "rgb_led.c"
                    INCLUDE_DIRS "."
                    REQUIRES wendy_core led_strip)
