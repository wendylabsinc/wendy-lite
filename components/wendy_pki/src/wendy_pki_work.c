#include "wendy_pki_work.h"
#include <string.h>
#if ESP_PLATFORM && CONFIG_WENDY_NET_PEER
#error "Native actor activation requires the serialized crypto-worker layer"
#endif
void wendy_pki_work_enable(void){}
bool wendy_pki_work_available(void){return false;}
bool wendy_pki_work_submit(void(*f)(void*),void*c){(void)f;(void)c;return false;}
bool wendy_pki_work_poll(void){return false;}
bool wendy_pki_work_start(void(*w)(void)){(void)w;return false;}
bool wendy_pki_work_stop(void){return true;}
bool wendy_pki_work_idle(void){return true;}
bool wendy_pki_work_is_current(void){return false;}
void wendy_pki_work_metrics(struct wendy_pki_work_metrics*m){if(m)memset(m,0,sizeof*m);}
bool wendy_pki_io_work_submit(void(*f)(void*),void*c){(void)f;(void)c;return false;}
bool wendy_pki_io_work_poll(void){return false;}
bool wendy_pki_io_work_idle(void){return true;}
int wendy_pki_work_run(void(*f)(void*),void*c){if(!f)return-1;f(c);return 0;}
void wendy_pki_work_bind_actor(void){}
bool wendy_pki_handshake_claim(void*p){return p!=0;}
bool wendy_pki_handshake_owned(void*p){return p!=0;}
void wendy_pki_handshake_release(void*p){(void)p;}
bool wendy_pki_handshake_available(void){return true;}
unsigned wendy_pki_handshake_mesh_limit(void){return 0;}
bool wendy_pki_handshake_transfer(void*a,void*b){return a&&b;}
bool wendy_pki_handshake_busy(void){return false;}
