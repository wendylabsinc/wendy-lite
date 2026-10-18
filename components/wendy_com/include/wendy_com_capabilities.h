#pragma once
#include "wendy_com_msg.pb.h"

/* Report what this firmware can actually execute before a host reserves a
 * Cloud asset. Local identity recovery does not require the Cloud task. */
static inline void wcom_enrollment_capabilities(WendyComEnrollmentChallenge *challenge)
{
    challenge->enrollment_reset_supported = false;
    challenge->has_cloud_enrollment_supported = true;
    challenge->cloud_enrollment_supported = false;
    challenge->has_mldsa_verification_supported = true;
    challenge->mldsa_verification_supported = false;
#if CONFIG_WENDY_PKI
    challenge->enrollment_reset_supported = true;
#endif
#if CONFIG_WENDY_PKI && CONFIG_WENDY_CLOUD && CONFIG_WENDY_WIFI_ENABLED
    challenge->cloud_enrollment_supported = true;
#endif
#if CONFIG_WENDY_PKI && CONFIG_MBEDTLS_SSL_TLS1_3_SIG_MLDSA65
    challenge->mldsa_verification_supported = true;
#endif
}
