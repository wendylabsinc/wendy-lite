#ifndef WENDY_COM_STDIO_PUMP_H
#define WENDY_COM_STDIO_PUMP_H

#include <stdbool.h>
#include <stdint.h>
#include "wendy_com_msg.pb.h"

// Streams the stdout/stderr data captured by wendy_com_stdio to an attached
// client, as console_data events. All functions must be called from the com
// task.

/**
 * Attach a client: buffered and future stdio data is sent to client_id as
 * console_data events carrying event_id. Re-attaching with the same
 * client_id/event_id just extends the deadline; a different attachment
 * replaces the current one. duration_ms bounds the attachment lifetime
 * (0 = forever). blocking_mode selects the stdio capture mode (see
 * wcom_stdio_set_blocking()) and is applied on every attach; detaching
 * always restores non-blocking mode.
 */
WendyComResult wcom_stdio_pump_attach(int client_id, uint32_t event_id, uint32_t duration_ms, bool blocking_mode);

/**
 * Detach the current attachment; fails if client_id/event_id don't match it.
 */
WendyComResult wcom_stdio_pump_detach(int client_id, uint32_t event_id);

/**
 * Drop the attachment held by client_id, if any.
 */
void wcom_stdio_pump_client_disconnected(int client_id);

#endif
