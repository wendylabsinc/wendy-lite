#pragma once
#include "wendy_com_msg.pb.h"
#if ESP_PLATFORM && CONFIG_SPIRAM
#include "esp_psram.h"
#endif

/* Report what this firmware can actually execute before a host reserves a
 * Cloud asset. Local identity recovery does not require the Cloud task. */
static inline void wcom_enrollment_capabilities(WendyComEnrollmentChallenge *challenge)
{
    challenge->enrollment_reset_supported = false;
    challenge->uuid_enrollment_supported = false;
    challenge->has_cloud_enrollment_supported = true;
    challenge->cloud_enrollment_supported = false;
    challenge->has_mldsa_verification_supported = true;
    challenge->mldsa_verification_supported = false;
#if CONFIG_WENDY_PKI
    challenge->enrollment_reset_supported = true;
    challenge->uuid_enrollment_supported = true;
#endif
#if CONFIG_WENDY_PKI && CONFIG_WENDY_CLOUD && CONFIG_WENDY_WIFI_ENABLED
    challenge->cloud_enrollment_supported = true;
#endif
    /* Rule (2026-11-10): Lite enrols on the P-256 (ES) chain by default and
     * opts into the ML-DSA chain only when the board has enough RAM. The
     * ML-DSA device chain is about 32 KB and is held in RAM while it is read;
     * without PSRAM that starves the board (WDY-4140). PSRAM present and
     * initialised is today's measure of "enough RAM"; the host picks the
     * P-256 Lite chain whenever this stays false. */
#if CONFIG_WENDY_PKI && CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65 && CONFIG_SPIRAM
#if ESP_PLATFORM
    challenge->mldsa_verification_supported = esp_psram_is_initialized();
#else
    challenge->mldsa_verification_supported = true;
#endif
#endif
}
