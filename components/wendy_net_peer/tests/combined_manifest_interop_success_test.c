/* Positive actual Go signatures over complete short-key service manifests. */
#include "catalog_internal.h"
#include "wendy_net_directory.h"
#include "wendy_pki_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char tenant[]="11111111-1111-4111-8111-111111111111";
static const char self[]="99999999-9999-4999-8999-999999999999";
static void *read_file(const char *directory,const char *name,size_t *size)
{
 char path[2048];assert(snprintf(path,sizeof path,"%s/%s",directory,name)>0);
 FILE *f=fopen(path,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>0 && n<65536);
 rewind(f);void *bytes=malloc((size_t)n);assert(bytes);assert(fread(bytes,1,(size_t)n,f)==(size_t)n);fclose(f);*size=(size_t)n;return bytes;
}
static uint64_t next_hop(void *context,const uint8_t device[16],uint64_t exclude)
{(void)context;(void)device;(void)exclude;return 1;}
int main(int argc,char **argv)
{
 assert(argc==2 && !wendy_pki_crypto_init());
 const char *names[]={"ecdsa","mldsa65"};
 const char *devices[]={"44444444-4444-4444-8444-444444444444","55555555-5555-4555-8555-555555555555"};
 for(unsigned profile=0;profile<2;profile++){
  struct wnd_directory *directory=calloc(1,sizeof *directory);assert(directory && !wnd_init(directory,tenant,self));
  struct wendy_pki_mesh_peer *peer=calloc(1,sizeof *peer);assert(peer);
  strcpy(peer->device,devices[profile]);peer->expires=1800003600;
  char name[80];snprintf(name,sizeof name,"%s-spki.der",names[profile]);size_t spki_size;
  void *spki=read_file(argv[1],name,&spki_size);assert(spki_size<=sizeof peer->spki);
  memcpy(peer->spki,spki,spki_size);peer->spki_size=spki_size;free(spki);assert(!wnd_identity(directory,peer));
  struct wnsc_node *catalog=NULL;struct wnsc_config config={.tenant=tenant,.device=self,.catalog_bytes=512*1024,.catalog_records=512,.next_hop=next_hop};
  assert(!wnsc_open(&catalog,&config));
  const unsigned counts[]={0,3,64};
  for(unsigned index=0;index<3;index++){
   snprintf(name,sizeof name,"%s-%u.cbor",names[profile],counts[index]);size_t size;
   void *wire=read_file(argv[1],name,&size);int64_t issued=INT64_C(1800000000000)+(int64_t)index*1000;
   assert(!wnd_accept(directory,wire,size,issued+1,1000+(int64_t)index*1000));
   struct wn_doc *doc=malloc(sizeof *doc);assert(doc);
   assert(!wn_doc_parse_array_view(doc,wire,size,WN_MANIFEST_WIRE_MAX,"services"));
   unsigned body=(unsigned)wn_doc_member(doc,0,"body");uint8_t device[16];assert(!wn_uuid_parse(devices[profile],device));
   assert(!wnsc_manifest_services(catalog,doc,body,device,index+1,issued,issued+900000,false));
   assert(catalog->records.count==counts[index]);
   for(struct wns_entry *e=catalog->records.entries;e;e=e->next)assert(e->generation==index+1 && e->expires==issued+900000);
   printf("%s: %u services, %zu byte signed artifact, verified exact Go body, summary bytes=%zu PASS\n",names[profile],counts[index],size,catalog->records.bytes);
   free(doc);free(wire);
  }
  wnsc_close(catalog);wnd_deinit(directory);free(directory);free(peer);
 }
 return 0;
}
