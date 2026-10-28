#include "topology_record.h"
#include "wendy_net_alloc.h"
#include "pb_encode.h"
#include <string.h>

static bool encode_principal(pb_ostream_t *stream,const pb_field_t *field,void *const *argument)
{
    const char *text=*argument;
    if(!text)return true;
    size_t size=strnlen(text,WNT_TOPOLOGY_PRINCIPAL_MAX+1);
    return size<=WNT_TOPOLOGY_PRINCIPAL_MAX &&
        pb_encode_tag_for_field(stream,field) && pb_encode_string(stream,(const uint8_t *)text,size);
}
int wnt_record_copy(WendyComNetTopologyPage *page,const struct wnt_record_view *view)
{
    char *principal=NULL;
    if(view->record.owner_role==WNT_TOPOLOGY_OPERATOR){
        if(!view->principal || !view->principal_size || view->principal_size>WNT_TOPOLOGY_PRINCIPAL_MAX ||
           memchr(view->principal,0,view->principal_size) || view->record.device.size ||
           view->record.owner_instance.size!=16)return -1;
        bool nonzero=false;
        for(unsigned i=0;i<16;i++)nonzero|=view->record.owner_instance.bytes[i]!=0;
        if(!nonzero)return -1;
        principal=wendy_net_malloc(view->principal_size+1);
        if(!principal)return -1;
        memcpy(principal,view->principal,view->principal_size);principal[view->principal_size]=0;
    }
    page->record=view->record;
    page->record.owner_principal=(pb_callback_t){0};
    if(principal){
        page->record.owner_principal.funcs.encode=encode_principal;
        page->record.owner_principal.arg=principal;
    }
    page->has_record=true;
    return 0;
}
void wnt_page_release(WendyComNetTopologyPage *page)
{
    if(page->record.owner_principal.funcs.encode==encode_principal)
        wendy_net_free(page->record.owner_principal.arg);
    page->record.owner_principal=(pb_callback_t){0};
}
