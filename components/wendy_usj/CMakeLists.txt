if(CONFIG_WENDY_USJ)
    idf_component_register(
        SRCS "src/wendy_usj.c"
        INCLUDE_DIRS "include"
        REQUIRES esp_driver_usb_serial_jtag vfs esp_log freertos wendy_com wendy_stdio nanopb
    )
    # Belt-and-suspenders: IDF's REQUIRES propagation for esp_driver_usb_serial_jtag
    # can fail when the build description is stale. Add the include path explicitly.
    idf_component_get_property(usj_dir esp_driver_usb_serial_jtag COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${usj_dir}/include")
    idf_component_get_property(vfs_dir vfs COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${vfs_dir}/include")
    idf_component_get_property(wendy_com_dir wendy_com COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${wendy_com_dir}/include")
    idf_component_get_property(wendy_stdio_dir wendy_stdio COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${wendy_stdio_dir}/include")
    idf_component_get_property(nanopb_dir nanopb COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${nanopb_dir}")
    # usb_serial_jtag_vfs.c is only compiled in the IDF component when
    # CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG_ENABLED=y, which we unset to avoid the
    # ROM secondary-console conflict. Add it to the component's own library so it
    # compiles with all the right include paths already configured.
    idf_component_get_property(usj_lib esp_driver_usb_serial_jtag COMPONENT_LIB)
    target_sources(${usj_lib} PRIVATE "${usj_dir}/src/usb_serial_jtag_vfs.c")
    target_include_directories(${usj_lib} PRIVATE "${vfs_dir}/include")
    target_link_libraries(${usj_lib} PRIVATE idf::vfs)
else()
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wendy_usj_stub.c" "/* usj disabled */\n")
    idf_component_register(
        SRCS "${CMAKE_CURRENT_BINARY_DIR}/wendy_usj_stub.c"
        INCLUDE_DIRS "include"
    )
endif()
