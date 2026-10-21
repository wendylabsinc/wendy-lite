# The pinned camera module applies the DVP fix to ESP-IDF. Fail the build if
# that step was skipped: partial frames must not reach the JPEG encoder.
find_package(Git REQUIRED)
idf_component_get_property(camera_module mosaico_module_camera COMPONENT_DIR)
get_filename_component(idf_parent "$ENV{IDF_PATH}" DIRECTORY)
execute_process(COMMAND "${CMAKE_COMMAND}" -E env
    --unset=GIT_DIR --unset=GIT_WORK_TREE "GIT_CEILING_DIRECTORIES=${idf_parent}"
    "${GIT_EXECUTABLE}" apply --no-index --reverse --check
    "${camera_module}/patches/esp-idf-dvp-frame-capture-stability.patch"
    WORKING_DIRECTORY "$ENV{IDF_PATH}"
    RESULT_VARIABLE dvp_result ERROR_VARIABLE dvp_error)
if(NOT dvp_result EQUAL 0)
    message(FATAL_ERROR "Mosaico DVP stability patch is missing: ${dvp_error}")
endif()

# Its second patch can silently skip every file when the sample sits inside
# a Git checkout. Apply it to a build copy with repository discovery disabled.
idf_component_get_property(sensor_source espressif__esp_cam_sensor COMPONENT_DIR)
idf_component_get_property(sensor_target espressif__esp_cam_sensor COMPONENT_LIB)
set(sensor_destination "${CMAKE_BINARY_DIR}/wendy_patched/mosaico_cam_sensor")
set(sensor_patch "${WENDY_LITE_ROOT}/patches/mosaico-sc101iot-pclk-delay.patch")
get_filename_component(sensor_parent "${sensor_source}" DIRECTORY)
execute_process(COMMAND "${CMAKE_COMMAND}" -E env
    --unset=GIT_DIR --unset=GIT_WORK_TREE "GIT_CEILING_DIRECTORIES=${sensor_parent}"
    "${GIT_EXECUTABLE}" apply --no-index --reverse --check "${sensor_patch}"
    WORKING_DIRECTORY "${sensor_source}"
    RESULT_VARIABLE sensor_patched OUTPUT_QUIET ERROR_QUIET)
if(sensor_patched EQUAL 0)
    wendy_prepare_patched_tree("${sensor_source}" "${sensor_destination}")
else()
    wendy_prepare_patched_tree("${sensor_source}" "${sensor_destination}" "${sensor_patch}")
endif()
wendy_redirect_dependency_target(${sensor_target} "${sensor_source}" "${sensor_destination}")

# Reserve the dashboard draw buffer before the sensor and network DMA users.
# Keep the pinned BSP intact, including its cached component hash.
idf_component_get_property(bsp_source esp-mosaico-bsp COMPONENT_DIR)
idf_component_get_property(bsp_target esp-mosaico-bsp COMPONENT_LIB)
set(bsp_destination "${CMAKE_BINARY_DIR}/wendy_patched/mosaico_bsp")
wendy_prepare_patched_tree("${bsp_source}" "${bsp_destination}"
    "${WENDY_LITE_ROOT}/patches/mosaico-display-dma-buffer.patch")
wendy_redirect_dependency_target(${bsp_target} "${bsp_source}" "${bsp_destination}")
