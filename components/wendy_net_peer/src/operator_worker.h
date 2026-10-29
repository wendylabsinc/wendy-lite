/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_net_operator.h"
#include "certificate_store.h"
#include <stdatomic.h>

struct wnop_job {
    atomic_uint references;atomic_bool done;
    int result;bool workspace_owned,cached;
    struct wendy_pki_mesh_identity clock;
    struct wncs_loan loan;
    
    uint8_t hashes[16][32];
    uint8_t *wire;size_t size;
    struct wendy_pki_operator_peer *peer;
};
struct wnop_primary_key {
    const char *principal;time_t expires;
    const uint8_t *spki;size_t spki_size;const uint8_t *leaf_hash;
};
/* One worker-owned immutable proof copy and pinned DER loan. Return0submitted,
 *1temporarybusy,2missingDER,-1invalid. Cached peer is independently verified
 * primary metadata scoped to this same enrollment/trust epoch. */
int wnop_job_start(struct wnop_job **,struct wncs_store *,const void *,size_t,
    const struct wendy_pki_mesh_identity *,const struct wnop_primary_key *);
void wnop_job_release(struct wnop_job *);
