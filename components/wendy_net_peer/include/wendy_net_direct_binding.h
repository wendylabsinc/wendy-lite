#pragma once
#include <stddef.h>
#include <stdint.h>

/* Both digests must be computed/validated locally: ordered authenticated
 * endpoint identities/instances/security epochs, and both frozen flow views.
 * The session actor enforces generation fencing and one-way promotion. */
struct wn_direct_attachment {
    uint8_t session_id[32];
    uint64_t generation;
    uint32_t attachment_id; /* nonzero, never reused on this TLS connection */
    uint8_t mode;           /* 0 BLE, 1 promoted */
    uint8_t coordinator_nonce[16], participant_nonce[16];
    uint8_t identity_digest[32], snapshot_digest[32];
};
int wn_direct_attachment_context(const struct wn_direct_attachment *a, uint8_t out[32]);
/* exporter comes from wendy_pki_mesh_channel_binding on the candidate TLS
 * connection with the above context. capability is the retained random session
 * secret, never a TLS ticket. Role is logical coordinator=0, participant=1. */
int wn_direct_attachment_proof(const uint8_t capability[32], const uint8_t exporter[32],
                               const uint8_t context[32], uint8_t role, uint8_t out[32]);
int wn_direct_attachment_verify(const uint8_t capability[32], const uint8_t exporter[32],
                                const uint8_t context[32], uint8_t role, const uint8_t *proof,
                                size_t size);

/* Per-flow promoted stream context. a is the locally committed promotion
 * transcript; open_digest is the retained immutable OPEN identity. Fresh
 * nonces belong to this individual stream, not the session's earlier offer.
 * Export label: EXPORTER-wendy-direct-promoted-flow/1. Use attachment_proof
 * with this context/exporter and the logical role; tickets grant no binding. */
int wn_direct_promoted_flow_context(const struct wn_direct_attachment *a, uint32_t flow_id,
                                    const uint8_t open_digest[32],
                                    const uint8_t coordinator_nonce[16],
                                    const uint8_t participant_nonce[16], uint8_t out[32]);

#define WN_DIRECT_PROMOTED_EXPORT_LABEL "EXPORTER-wendy-direct-promoted-flow/1"
/* Fixed-storage incremental stream handshake, owned by one session actor.
 * Authenticate the upper endpoint, exclusively claim/freeze this flow, and
 * validate the committed transcript before init. No backend OPEN occurs here.
 * The exporter MUST be for the candidate upper TLS connection and above label.
 * Dial direction (initiator) is independent of logical role. The actor elects
 * exactly one initiator and supplies a fresh nonce for each candidate.
 *
 * output returns a borrowed suffix; call sent only for bytes accepted by TLS.
 * input consumes at most its current flight; caller must retain excess bytes.
 * Never deliver app bytes until done. commit_possible is sticky: on failure
 * after it becomes true terminate the flow, since the peer may be using raw
 * bytes. Before it becomes true a fresh candidate may be tried. Deadline,
 * authorization invalidation, transport errors and old-worker joins belong to
 * the owner. Charge sizeof this struct to the connection's network budget. */
struct wn_direct_promoted_binding {
    uint8_t attachment_context[32], capability[32], open_digest[32];
    /* Hello identity/nonces are dead after derivation; never overlap wire bytes
     * still borrowed by a partial TLS write. Keep request/attachment hashes for commit. */
    union {
        struct {
            uint8_t hello[40], nonce[16];
        } initial;
        struct {
            uint8_t context[32], exported[32];
        } derived;
    } scratch;
    uint8_t wire[64];
    uint32_t flow_id;
    size_t offset, size;
    int (*exporter)(void *, const char *, const uint8_t[32], uint8_t[32]);
    void *export_arg;
    uint8_t role, state;
    uint8_t initiator, commit_possible, done, failed;
};
int wn_direct_promoted_init(struct wn_direct_promoted_binding *,
                            const struct wn_direct_attachment *, uint32_t flow_id,
                            const uint8_t open_digest[32], const uint8_t capability[32],
                            uint8_t role, const uint8_t nonce[16], int initiator,
                            int (*exporter)(void *, const char *, const uint8_t[32], uint8_t[32]),
                            void *);
int wn_direct_promoted_output(struct wn_direct_promoted_binding *, const uint8_t **, size_t *);
int wn_direct_promoted_sent(struct wn_direct_promoted_binding *, size_t);
int wn_direct_promoted_input(struct wn_direct_promoted_binding *, const uint8_t *, size_t,
                             size_t *used);

struct wn_direct_upper;
/* One nonblocking handshake step. Reads only the current flight, leaving raw
 * application bytes in TLS even when READY and payload arrive together.
 * Caller owns authentication, deadline, exclusive claim and eventual commit. */
int wn_direct_promoted_poll(struct wn_direct_promoted_binding *, const struct wn_direct_upper *);
