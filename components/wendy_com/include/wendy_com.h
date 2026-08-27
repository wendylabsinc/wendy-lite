#ifndef WENDY_COM_H
#define WENDY_COM_H

#include "wendy_com_common.h"

void wcom_set_app_delegate(const struct wcom_app_delegate *delegate);
void wcom_start(void);
void wcom_exec(struct wcom_operation *op);
bool wcom_is_running(void);

#endif
