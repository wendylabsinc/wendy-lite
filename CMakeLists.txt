cmake_minimum_required(VERSION 3.29)

# WAMR component declares cmake_minimum_required(VERSION 3.5) which
# CMake 4.x rejects. Allow it via the compatibility policy.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wendy_mcu)

# ESP32-P4 ships in several board layouts that differ in flash size and
# partition table, so a board overlay must be selected explicitly:
#     idf.py @boards/waveshare_lcd_4b.cfg   set-target esp32p4
#     idf.py @boards/dfr1172_firebeetle.cfg set-target esp32p4
# Each boards/<board>.defaults sets CONFIG_WENDY_P4_BOARD_NAME.
if(IDF_TARGET STREQUAL "esp32p4")
    if(CONFIG_WENDY_P4_BOARD_NAME STREQUAL "")
        message(FATAL_ERROR
            "ESP32-P4 requires an explicit board overlay. Re-run set-target with one of:\n"
            "  idf.py @boards/waveshare_lcd_4b.cfg   set-target esp32p4\n"
            "  idf.py @boards/dfr1172_firebeetle.cfg set-target esp32p4\n"
            "(see boards/ and the ESP32-P4 notes in README.md)")
    endif()
    message(STATUS "wendy-lite: ESP32-P4 board = ${CONFIG_WENDY_P4_BOARD_NAME}")
endif()
