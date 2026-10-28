/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_pki_mesh.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct wncd_job;
enum wncd_phase {WNCD_IDLE,WNCD_REQUESTED,WNCD_RUNNING,WNCD_READY,WNCD_CONSUMED};
/* One node-wide read effect, with no inline DER buffer while idle. Protocol
 * state uses request/read/release only. The outer driver owns poll/close and
 * supplies worker completions; it never lends the node/store/TLS context. */
struct wncd_reader {
    enum wncd_phase phase;
    uint64_t owner,generation;
    uint32_t certificate_epoch;
    uint8_t hash[32];
    size_t offset,total;
    int result;
    int64_t retry_at;
    const uint8_t *bytes;
    struct wncd_job *job;
};
/* Pure state transition/copy: no submission, NVS, hashing or context access.
 * Returns bytes ready, -2 pending/another owner, -1 unavailable/invalid.
 * A ready result remains until release, including send-queue backpressure.
 * NULL output probes readiness without copying. */
int wncd_read(struct wncd_reader *,uint64_t owner,
    uint64_t generation,uint32_t certificate_epoch,const uint8_t hash[32],
    size_t offset,size_t expected_total,uint8_t out[1024],size_t *total);
void wncd_release(struct wncd_reader *,uint64_t owner,
    const uint8_t hash[32],size_t offset);
/* Outer-driver effects. current also binds the request's captured generation
 * and certificate epoch to the current node index. now is monotonic usec. */
int wncd_poll(struct wncd_reader *,const struct wendy_pki_mesh_identity *,bool current,int64_t now);
int64_t wncd_deadline(const struct wncd_reader *);
void wncd_cancel(struct wncd_reader *,uint64_t owner);
void wncd_close(struct wncd_reader *);
