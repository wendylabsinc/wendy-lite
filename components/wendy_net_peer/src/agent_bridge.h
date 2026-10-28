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
/* Abort application I/O and queue a com-task acknowledgement. Keep the actor
 * lease/admission slot until retired(), then release that final lease. */
void wnab_close(struct wnab_bridge *);
bool wnab_retired(struct wnab_bridge *);
void wnab_release(struct wnab_bridge *);
unsigned wnab_live(void);
