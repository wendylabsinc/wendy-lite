/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_pki_mesh.h"

/* Diagnostics only: these functions never initialize trust, set time or
 * authorize an operation. Boot must be called before normal PKI effects. */
/* Capture now; delivery waits until the existing console ring is ready. */
void wendy_pki_clock_observe_boot(void);
void wendy_pki_clock_observe_console_ready(void);
void wendy_pki_clock_observe_first_remote(const struct wendy_pki_mesh_identity *);

struct pki_clock_observation_raw {
    int64_t utc_us;
    bool valid;
};
struct pki_clock_observation_raw pki_clock_observation_read_raw(void);
/* Writers below are serialized by the existing PKI identity lock. */
void pki_clock_observation_publish_clock(uint64_t generation,
                                        const struct wendy_pki_certificate_time *);
void pki_clock_observation_publish_proof(uint64_t generation, time_t seconds, int64_t monotonic_us);
/* Identity reset clears current snapshots, but not this boot's proof-ever or
 * once-only event latches. All state is BSS/RAM, with no persistent writes. */
void pki_clock_observation_reset(void);
void pki_clock_observation_direct_apply(struct pki_clock_observation_raw before,
                                         struct pki_clock_observation_raw after,
                                         uint64_t generation, bool already_sufficient);
