/* Inactive settings contract until the supported WendyCom cutover. */
#include "settings.h"
esp_err_t wn_settings_init(void){return ESP_OK;}
WendyComNetConfig wn_settings_get(void){return (WendyComNetConfig){0};}
bool wn_settings_restarting(void){return false;}
bool wn_settings_restart_due(void){return false;}
