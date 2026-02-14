set(srcs "")
set(requires "")

if(CONFIG_WENDY_USB_CDC_ENABLED)
    list(APPEND srcs "src/wendy_usb.c")
    list(APPEND requires tinyusb esp_rom esp_system freertos)
endif()

if(NOT srcs)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_usb_stub.c" "/* USB disabled */\n")
    list(APPEND srcs "${CMAKE_CURRENT_BINARY_DIR}/wendy_usb_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES ${requires}
)
