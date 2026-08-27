#include "wendy_com.h"
#include "wendy_com_agent.h"
#include "wendy_com_stdio.h"
#include "wendy_com_link.h"
#include "wendy_com_cmd.h"
#include <stdatomic.h>


static atomic_bool _is_running;


static void _on_ready(struct wcom_operation *op)
{
    _is_running = true;
}

void wcom_set_app_delegate(const struct wcom_app_delegate *delegate)
{
    wcom_cmd_set_app_delegate(delegate);
}

void wcom_start(void)
{
    wcom_stdio_init();
    wcom_core_init();
    wcom_agent_init();

    static struct wcom_operation op = {
        .func = _on_ready
    };
    wcom_core_exec(&op);
}

void wcom_exec(struct wcom_operation *op)
{
    wcom_core_exec(op);
}

bool wcom_is_running(void)
{
    return _is_running;
}
