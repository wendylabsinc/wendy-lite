#ifndef WENDY_COM_CMD_H
#define WENDY_COM_CMD_H

#include <stdint.h>
#include <stddef.h>
#include "wendy_com_msg.pb.h"
#include "wendy_com_common.h"

WendyComResult wcom_cmd_ping(void);
WendyComResult wcom_cmd_reboot(void);
WendyComResult wcom_cmd_app_push_begin(int client_id, size_t size, WendyComAppType app_type);
WendyComResult wcom_cmd_app_push_data(int client_id, size_t offset, const uint8_t *data, size_t size);
WendyComResult wcom_cmd_app_push_end(int client_id);
WendyComResult wcom_cmd_app_start(int client_id);
WendyComResult wcom_cmd_app_stop(int client_id);
WendyComResult wcom_cmd_get_device_identity(WendyComDeviceIdentity *out);
WendyComResult wcom_cmd_get_device_info(WendyComDeviceInfo *out);
WendyComResult wcom_cmd_console_attach(int client_id, uint32_t event_id, uint32_t duration_ms, bool blocking);
WendyComResult wcom_cmd_console_detach(int client_id, uint32_t event_id);

void wcom_cmd_client_disconnected(int client_id);

void wcom_cmd_set_app_delegate(const struct wcom_app_delegate *delegate);

#endif
