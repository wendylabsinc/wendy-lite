#pragma once
#include "wendy_pki_mesh.h"
#include "wendy_net_alloc.h"
#include <stdbool.h>
/* Each future is owned by the affected protocol operation. Only a successfully
 * submitted job owns an input copy/workspace; busy submission allocates none
 * persistently. One whole signature call executes on the crypto worker. */
struct wncrypto_job;
/* Actor-owned completion projections. No connection loan or input bytes remain
 * after take. A signing receipt owns only its scheme-sized output buffer.
 * Verification binds the exact principal/body/key/signature;
 * signing additionally binds the live session and own certificate fingerprint. */
struct wncrypto_verdict {
    uint8_t input[32]; /* Includes the exact certified key bytes. */
    int result;unsigned kind;bool valid;
};
struct wncrypto_signature {
    uint8_t digest[32],fingerprint[32];
    uint8_t *signature;
    wendy_pki_connection *connection;
    size_t signature_size;int result;unsigned kind;bool valid;
};
static inline void wncrypto_signature_clear(struct wncrypto_signature *completed)
{
    if(completed){wendy_net_free(completed->signature);*completed=(struct wncrypto_signature){0};}
}
bool wncrypto_take_verification(struct wncrypto_job **,struct wncrypto_verdict *);
bool wncrypto_take_signature(struct wncrypto_job **,struct wncrypto_signature *);
int wncrypto_verify_cached(struct wncrypto_job **,struct wncrypto_verdict *,unsigned,
    const struct wendy_pki_mesh_key *,const char *,const void *,size_t,const uint8_t *,size_t);
int wncrypto_sign_cached(struct wncrypto_job **,struct wncrypto_signature *,unsigned,
    wendy_pki_connection *,const char *,const void *,size_t,const uint8_t **,size_t *);
/* kind: 0 complete device manifest. 0 complete, 1 pending, -1 failure. */
int wncrypto_verify(struct wncrypto_job **,unsigned,const struct wendy_pki_mesh_key *,
    const char *,const void *,size_t,const uint8_t *,size_t);
void wncrypto_cancel(struct wncrypto_job **);
bool wncrypto_borrowed(wendy_pki_connection *);

bool wncrypto_ready(const struct wncrypto_job *);
