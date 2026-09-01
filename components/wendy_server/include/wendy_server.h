
#ifndef WENDY_SERVER_H
#define WENDY_SERVER_H

/// Start the mTLS server task and register its mDNS service. The names it
/// publishes come from wendy_conf, so wendy_conf_init() must have run first.
void wendy_server_start(void);

#endif
