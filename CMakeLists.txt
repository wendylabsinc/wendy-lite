cmake_minimum_required(VERSION 3.29)

# WAMR component declares cmake_minimum_required(VERSION 3.5) which
# CMake 4.x rejects. Allow it via the compatibility policy.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wendy_mcu)
