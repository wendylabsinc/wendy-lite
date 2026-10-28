#pragma once
#include "../../Sources/CWendyLite/include/wendy_services.h"
long long sys_uptime_ms(void);
void replay_test_time(long long);
void replay_test_epoch(unsigned);
void replay_test_busy(void);
void replay_test_restart(void);
unsigned replay_test_publications(void);
unsigned replay_test_withdrawals(void);
