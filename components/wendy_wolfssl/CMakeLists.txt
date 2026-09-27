# Pinned upstream wolfSSL supplies TLS/X.509 and cryptographic primitives.
if(CONFIG_WENDY_PKI)
    file(GLOB srcs "wolfssl/src/*.c" "wolfssl/wolfcrypt/src/*.c")
    list(FILTER srcs EXCLUDE REGEX "/(evp|bio|misc|ext_mlkem|ext_lms|ext_xmss)\\.c$")
    idf_component_register(SRCS ${srcs} "random.c" INCLUDE_DIRS "include" "wolfssl"
                           REQUIRES lwip freertos esp_hw_support pthread)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC WOLFSSL_USER_SETTINGS)
    target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)
else()
    idf_component_register(INCLUDE_DIRS "include" REQUIRES lwip freertos esp_hw_support pthread)
endif()
