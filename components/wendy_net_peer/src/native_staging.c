#include "wendy_net_peer.h"
#include "wendy_net_agent.h"
#include <unistd.h>
esp_err_t wendy_net_app_start(void){return ESP_OK;}
bool wendy_net_app_ready(void){return false;}
int wendy_net_app_listener(void){return -1;}
bool wendy_net_app_management_ready(void){return true;}
void wendy_net_app_accept(int fd){close(fd);}
esp_err_t wendy_net_app_connect(const char *p,uint16_t s,wendy_pki_connection **c){(void)p;(void)s;if(c)*c=NULL;return ESP_ERR_NOT_SUPPORTED;}
esp_err_t wendy_net_app_refresh_time(const char *p,struct wendy_pki_mesh_identity *i){(void)p;(void)i;return ESP_ERR_NOT_SUPPORTED;}
int wendy_net_app_time_listener(void){return -1;}
void wendy_net_app_test_start(const char *p){(void)p;}
int wendy_net_app_poll(void){return 0;}
bool wendy_net_app_stop(void){return true;}
void wendy_net_app_watch(fd_set *r,fd_set *w,int *m,int64_t *d){(void)r;(void)w;(void)m;(void)d;}
void wendy_net_agent_start(void){}
void wendy_net_agent_accept(int fd){close(fd);}
int wendy_net_agent_poll(void){return 0;}
bool wendy_net_agent_stop(void){return true;}
void wendy_net_agent_watch(fd_set *r,fd_set *w,int *m,int64_t *d){(void)r;(void)w;(void)m;(void)d;}
