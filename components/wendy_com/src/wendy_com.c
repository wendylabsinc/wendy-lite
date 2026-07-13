#include "wendy_com.h"
#include "wendy_com_agent.h"
#include "wendy_com_stdio.h"
#include "wendy_com_link.h"
#include "wendy_com_cmd.h"

void wcom_set_app_delegate(const struct wcom_app_delegate *delegate)
{
    wcom_cmd_set_app_delegate(delegate);
}

void wcom_start(void)
{
    wcom_stdio_init();
    wcom_core_init();
    wcom_agent_init();
}

void wcom_exec(struct wcom_operation *op)
{
    wcom_core_exec(op);
}
