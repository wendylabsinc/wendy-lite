/* Plaintext boundary: mesh actor owns TLS; WendyCom owns its application logic. */
#pragma once
#include "agent_pipe.h"
#include "wendy_com_link.h"
struct wnab_bridge;
struct wnab_bridge *wnab_open(enum wcom_link_permission,unsigned capacity);
struct wnap_ring *wnab_incoming(struct wnab_bridge *);
struct wnap_ring *wnab_outgoing(struct wnab_bridge *);
void wnab_input_eof(struct wnab_bridge *);
void wnab_notify(struct wnab_bridge *);
bool wnab_closed(struct wnab_bridge *);
/* Snapshot the pending receipt before sampling outgoing pipe/TLS output.
 * A later producer receipt must not be completed from an earlier empty sample. */
uint32_t wnab_output_receipt(struct wnab_bridge *);
/* Actor-only. Completes the sampled receipt once output has drained; a newer
 * receipt wins the comparison and waits for the next actor pass. */
void wnab_output_drained(struct wnab_bridge *,uint32_t receipt);
/* Abort application I/O and queue a com-task acknowledgement. Keep the actor
 * lease/admission slot until retired(), then release that final lease. */
void wnab_close(struct wnab_bridge *);
bool wnab_retired(struct wnab_bridge *);
void wnab_release(struct wnab_bridge *);
unsigned wnab_live(void);
