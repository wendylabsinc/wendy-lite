
#ifndef WENDY_SERVER_H
#define WENDY_SERVER_H

#include <stdbool.h>

struct wendy_server_caps {
    bool sensor_link;
};

/// Set the capabilities of the server.
/// Must be invoked before starting the server.
void wendy_server_set_caps(const struct wendy_server_caps caps);

/// Start the mTLS server task and register its mDNS service. The names it
/// publishes come from wendy_conf, so wendy_conf_init() must have run first.
void wendy_server_start(void);

#endif
