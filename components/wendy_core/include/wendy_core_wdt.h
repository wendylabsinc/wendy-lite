#ifndef WENDY_CORE_WDT_H
#define WENDY_CORE_WDT_H

/* Feeds the RTC watchdog once, immediately. Call as the very first thing
 * wendy_core_init() does. */
void wendy_core_wdt_feed(void);

/* Arms a periodic timer that keeps feeding the RTC watchdog as long as the
 * wendy_com task stays responsive. Call once wcom_start() has run. */
void wendy_core_wdt_start(void);

#endif
