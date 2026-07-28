#ifndef WENDY_COM_AGENT_H
#define WENDY_COM_AGENT_H

#include <stdint.h>


//--- literals ---//

#define WCOM_AGENT_MSG_MAGIC 0xA5
#define WCOM_AGENT_MSG_VERSION 2


//--- types ---//

/// Framing of every message exchanged with the host.
struct wcom_agent_msg_header {
    uint8_t magic;
    uint8_t version;
    uint8_t category;
    uint8_t channel;
    uint16_t reserved;
    uint16_t body_size; // big-endian
};


//--- functions ---//

void wcom_agent_init(void);

int wcom_get_link_id(int client_id);
int wcom_get_channel(int client_id);


#endif
