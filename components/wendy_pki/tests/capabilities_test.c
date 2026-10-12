#include "wendy_com_capabilities.h"
#include <assert.h>
#include <pb_decode.h>
#include <pb_encode.h>

int main(void)
{
    WendyComEnrollmentChallenge challenge = WendyComEnrollmentChallenge_init_zero;
    /* Clear preexisting values so a reused response cannot retain capabilities. */
    challenge.enrollment_reset_supported = !EXPECT_RESET;
    challenge.cloud_enrollment_supported = !EXPECT_CLOUD;
    challenge.mldsa_verification_supported = !EXPECT_MLDSA;
    wcom_enrollment_capabilities(&challenge);
    assert(challenge.has_cloud_enrollment_supported);
    assert(challenge.enrollment_reset_supported == EXPECT_RESET);
    assert(challenge.cloud_enrollment_supported == EXPECT_CLOUD);
    assert(challenge.has_mldsa_verification_supported);
    assert(challenge.mldsa_verification_supported == EXPECT_MLDSA);

    /* Explicit false must survive the wire, distinct from a legacy omission. */
    uint8_t wire[WendyComEnrollmentChallenge_size];
    pb_ostream_t output = pb_ostream_from_buffer(wire, sizeof wire);
    assert(pb_encode(&output, WendyComEnrollmentChallenge_fields, &challenge));
    WendyComEnrollmentChallenge decoded = WendyComEnrollmentChallenge_init_zero;
    pb_istream_t input = pb_istream_from_buffer(wire, output.bytes_written);
    assert(pb_decode(&input, WendyComEnrollmentChallenge_fields, &decoded));
    assert(decoded.has_cloud_enrollment_supported);
    assert(decoded.cloud_enrollment_supported == EXPECT_CLOUD);
    assert(decoded.has_mldsa_verification_supported);
    assert(decoded.mldsa_verification_supported == EXPECT_MLDSA);
    input = pb_istream_from_buffer(wire, 0);
    assert(pb_decode(&input, WendyComEnrollmentChallenge_fields, &decoded));
    assert(!decoded.has_cloud_enrollment_supported);
    assert(!decoded.has_mldsa_verification_supported);
    return 0;
}
