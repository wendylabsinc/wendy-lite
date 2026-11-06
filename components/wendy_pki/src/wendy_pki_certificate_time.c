/* SPDX-License-Identifier: Apache-2.0 */
#include "wendy_pki_certificate_time.h"
#include <pthread.h>
/* This lock protects two scalars only. It is never held across another lock,
 * certificate work, storage or I/O. TLS callbacks never take identity_lock. */
static pthread_mutex_t certainty_lock = PTHREAD_MUTEX_INITIALIZER;
static bool certain;
static uint64_t certain_generation;
bool wendy_pki_certificate_generation_uncertain(uint64_t generation)
{
    pthread_mutex_lock(&certainty_lock);
    bool result = !certain || certain_generation != generation;
    pthread_mutex_unlock(&certainty_lock);
    return result;
}
void wendy_pki_certificate_mark_certain(uint64_t generation)
{
    pthread_mutex_lock(&certainty_lock);
    certain_generation = generation;
    certain = true;
    pthread_mutex_unlock(&certainty_lock);
}
void wendy_pki_certificate_reset_certainty(void)
{
    pthread_mutex_lock(&certainty_lock);
    certain = false;
    pthread_mutex_unlock(&certainty_lock);
}
