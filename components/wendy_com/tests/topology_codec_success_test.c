/* Ordinary cross-language reply fixture; no private/signature material. */
#include "wendy_com_msg.pb.h"
#include "../../wendy_net_peer/src/topology_record.h"
#include <pb_encode.h>
#include <pb_decode.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
static size_t operator_wire(uint8_t *wire,size_t capacity,bool longest)
{
 WendyComMessage message=WendyComMessage_init_zero;message.which_msg=WendyComMessage_response_tag;
 message.msg.response.request_id=7;message.msg.response.which_data=WendyComResponse_net_topology_tag;
 WendyComNetTopologyPage *page=&message.msg.response.data.net_topology;
 const uint8_t tenant[16]={0x11,0x11,0x11,0x11,0x11,0x11,0x41,0x11,0x81,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
 const uint8_t instance[16]={0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0x4a,0xaa,0x8a,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
 const uint8_t address[16]={0xfd,0x45,0xb8,0x91,0x56,0x80,0x0c,0xca,0x1c,0xd7,0xf6,0x5e,0xb5,0x81,0x10,0x1b};
 memcpy(page->tenant,tenant,16);memset(page->device,0xbb,16);page->device[6]=0x4b;page->device[8]=0x8b;
 page->captured_at_unix_ms=1800000000123;page->generation=42;page->runtime_available=true;
 char principal[WNT_TOPOLOGY_PRINCIPAL_MAX+1]="spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/operator/Alice";
 if(longest){size_t prefix=strlen(principal)-5;memset(principal+prefix,'A',WNT_TOPOLOGY_PRINCIPAL_MAX-prefix);principal[WNT_TOPOLOGY_PRINCIPAL_MAX]=0;}
 struct wnt_record_view view={.record=WendyComNetTopologyRecord_init_zero,.principal=principal,.principal_size=strlen(principal)};
 view.record.kind=3;view.record.owner_role=WNT_TOPOLOGY_OPERATOR;
 view.record.address.size=view.record.owner_instance.size=16;
 memcpy(view.record.address.bytes,address,16);memcpy(view.record.owner_instance.bytes,instance,16);
 view.record.router_id=UINT64_MAX-1;view.record.revision=UINT64_MAX;view.record.authorized=true;
 assert(!wnt_record_copy(page,&view) && !page->record.device.size);
 memset(principal,'X',strlen(principal)); /* The actor source can retire now. */
 pb_ostream_t sizing=PB_OSTREAM_SIZING;assert(pb_encode(&sizing,WendyComMessage_fields,&message));
 pb_ostream_t stream=pb_ostream_from_buffer(wire,capacity);assert(pb_encode(&stream,WendyComMessage_fields,&message));
 assert(stream.bytes_written==sizing.bytes_written);
 /* A failed encoding still releases the one immutable principal exactly once. */
 uint8_t small[4];pb_ostream_t limited=pb_ostream_from_buffer(small,sizeof small);
 assert(!pb_encode(&limited,WendyComMessage_fields,&message));
 wnt_page_release(page);wnt_page_release(page);
 return stream.bytes_written;
}
int main(int argc,char **argv){
 WendyComMessage message=WendyComMessage_init_zero;
 message.which_msg=WendyComMessage_response_tag;
 WendyComResponse *response=&message.msg.response;response->request_id=7;
 response->which_data=WendyComResponse_net_topology_tag;
 WendyComNetTopologyPage *page=&response->data.net_topology;
 for(unsigned i=0;i<16;i++){page->tenant[i]=(uint8_t)(i+1);page->device[i]=(uint8_t)(i+17);}
 page->captured_at_unix_ms=1800000000123;page->generation=42;page->next_cursor=1;page->runtime_available=true;
 page->has_status=true;page->status.has_desired=true;page->status.desired.enabled=true;
 page->status.desired.ble=true;page->status.state=WendyComNetState_WENDY_COM_NET_RUNNING;
 page->status.active_links=1;page->has_record=true;page->record.kind=1;
 page->record.device.size=page->record.address.size=16;
 for(unsigned i=0;i<16;i++){page->record.device.bytes[i]=(uint8_t)(i+33);page->record.address.bytes[i]=(uint8_t)(i+49);}
 page->record.link_id=9;page->record.metric=8192;page->record.transport=2;
 uint8_t wire[1536];
 if(argc==2 && !strcmp(argv[1],"--emit-operator")){
  size_t size=operator_wire(wire,sizeof wire,false);
  for(size_t i=0;i<size;i++)printf("%02x",wire[i]);puts("");return 0;
 }
pb_ostream_t stream=pb_ostream_from_buffer(wire,sizeof wire);
 assert(pb_encode(&stream,WendyComMessage_fields,&message));
 assert(stream.bytes_written<sizeof wire && sizeof *page<=512);
 if(argc==2 && !strcmp(argv[1],"--emit")){
  for(size_t i=0;i<stream.bytes_written;i++)printf("%02x",wire[i]);puts("");return 0;
 }
 assert(argc==2);FILE *fixture=fopen(argv[1],"r");assert(fixture);
 for(size_t i=0;i<stream.bytes_written;i++){unsigned byte;assert(fscanf(fixture,"%2x",&byte)==1 && byte==wire[i]);}
 fclose(fixture);
 WendyComMessage decoded=WendyComMessage_init_zero;
 pb_istream_t input=pb_istream_from_buffer(wire,stream.bytes_written);
 assert(pb_decode(&input,WendyComMessage_fields,&decoded));
 assert(decoded.msg.response.data.net_topology.record.metric==8192);
 assert(decoded.msg.response.data.net_topology.captured_at_unix_ms==INT64_C(1800000000123));
 size_t op_size=operator_wire(wire,sizeof wire,false);assert(op_size<=1408);
 size_t max_size=operator_wire(wire,sizeof wire,true);assert(max_size<=1408);
 printf("PASS topology nanopb/Go fixture: device=%zu operator=%zu max_principal_row=%zu fixed_page=%zu\n",stream.bytes_written,op_size,max_size,sizeof *page);
 return 0;
}
