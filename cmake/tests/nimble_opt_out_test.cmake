cmake_minimum_required(VERSION 3.20)
# CONFIG_WENDY_BLE_PATCH_NIMBLE=n is accepted only on ESP-IDF development
# builds. Check how IDF_VER values are classified.
include("${CMAKE_CURRENT_LIST_DIR}/../../components/wendy_ble/cmake/nimble_patches.cmake")

set(development
    "v6.2-dev"
    "v6.2-dev-1234-g1c42e514c9"
    "v6.2-dev-1234-g1c42e514c9-dirty"
    "1c42e51"
    "1c42e514c9-dirty")
set(refused
    "v6.2"
    "v6.2.1"
    "v6.2-dirty"
    "v6.2.0"
    "v6.2-beta1"
    "v6.2-rc1"
    "v6.2-rc1-12-g1c42e51"
    "v6.1.1-5-g0123abc"
    "v6.0.3"
    "v6.1")

foreach(idf_ver IN LISTS development)
    wendy_ble_idf_is_development(result "${idf_ver}")
    if(NOT result)
        message(FATAL_ERROR "'${idf_ver}' must count as an ESP-IDF development build")
    endif()
endforeach()
foreach(idf_ver IN LISTS refused)
    wendy_ble_idf_is_development(result "${idf_ver}")
    if(result)
        message(FATAL_ERROR "'${idf_ver}' must not count as an ESP-IDF development build")
    endif()
endforeach()
wendy_ble_idf_is_development(result "")
if(result)
    message(FATAL_ERROR "An empty IDF_VER must not count as an ESP-IDF development build")
endif()
