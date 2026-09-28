#ifndef WENDY_COM_H
#define WENDY_COM_H

#include "wendy_com_common.h"

#ifdef __cplusplus
extern "C" {
#endif

void wcom_set_app_delegate(const struct wcom_app_delegate *delegate);
void wcom_set_sensor_link_delegate(const struct wcom_sensor_link_delegate *delegate);
void wcom_start(void);
// Pass-through to wcom_core_exec(); see wendy_com_link.h for the ownership
// rules that apply to *op.
void wcom_exec(struct wcom_operation *op);
bool wcom_is_running(void);

#ifdef __cplusplus
}
#endif

#endif
