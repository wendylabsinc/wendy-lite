/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "certificate_fetch.h"
#include "certificate_store.h"
#include "wendy_pki_mesh.h"
#include <stdatomic.h>
struct wncv_job {
    atomic_uint references;
    atomic_bool done;
    int result;
    bool workspace_owned;
    struct wncf_chain chain;
    struct wncs_loan loan;
    struct wendy_pki_mesh_identity clock;
    struct wendy_pki_mesh_peer peer;
};
/* Work owns a separate reference and a cache-independent immutable DER loan.
 * Closing the last carrier/store may drop its reference while work finishes. */
int wncv_start(struct wncv_job **,struct wncs_store *,const struct wncf_chain *,
                const struct wendy_pki_mesh_identity *);
void wncv_release(struct wncv_job *);
