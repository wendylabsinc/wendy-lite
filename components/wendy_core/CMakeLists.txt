idf_component_register(
    SRCS "src/wendy_core.c"
    INCLUDE_DIRS "include"
    REQUIRES wendy_conf wendy_stdio wendy_usj wendy_wifi nvs_flash esp_partition app_update
)

# COMPONENT_VERSION is set by the IDF Component Manager from the top-level
# `version:` field of idf_component.yml. It is the empty string when the
# manifest declares no version.
idf_component_get_property(wendy_core_version wendy_core COMPONENT_VERSION)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WENDY_CORE_COMPONENT_VERSION="${wendy_core_version}")
