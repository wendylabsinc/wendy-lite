#include "wendy_pki_est.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static FILE *fixture(const char *dir, const char *name)
{
    char path[1024];
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    assert(n > 0 && (size_t)n < sizeof path);
    FILE *in = fopen(path, "rb");
    assert(in);
    return in;
}
static struct pki_est_cert cert(const char *dir, const char *name)
{
    FILE *in = fixture(dir, name);
    uint8_t *data = malloc(PKI_EST_MAX_CERT_SIZE);
    assert(data);
    size_t n = fread(data, 1, PKI_EST_MAX_CERT_SIZE, in);
    assert(!ferror(in) && n);
    fclose(in);
    return (struct pki_est_cert){data,n};
}
static void feed(struct pki_est_stream *s, const char *dir, const char *name, size_t width)
{
    FILE *in = fixture(dir,name);
    uint8_t buffer[2048];
    size_t n;
    assert(width <= sizeof buffer);
    while ((n=fread(buffer,1,width,in)))
        assert(!pki_est_feed(s,buffer,n));
    assert(!ferror(in) && pki_est_complete(s));
    fclose(in);
}
static int verify(const char *dir, const char *name, int expected, const char *own_name)
{
    struct pki_est_cert own=cert(dir,own_name);
    struct pki_est_stream lite={0}, reg={0};
    struct pki_est_classical_scope scope={0};
    feed(&lite,dir,"lite.cms.b64",257);
    if (pki_est_lite_order(&lite,"f8640111-6f74-4336-82b1-d3195cab40dc",&own,&scope)) {
        assert(expected==-1);
        printf("%s: rejected wrong Lite key\n", name);
        goto done;
    }
    reg.keep=pki_est_keep_regular;
    reg.context=&scope;
    feed(&reg,dir,name,263);
    size_t wire=reg.wire, staged=reg.stored;
    int result=pki_est_regular_pins(&reg,&lite.certs[0],&scope,time(NULL));
    if (expected<0) assert(result);
    else {
        assert(!result && reg.count==(size_t)expected);
        static const char *wanted[]={"new-device.der","new-operator.der","old-device.der","old-operator.der"};
        for (int i=0; i<expected; i++) {
            struct pki_est_cert w=cert(dir,wanted[i]);
            unsigned found=0;
            for(size_t j=0;j<reg.count;j++)
                if(w.size==reg.certs[j].size&&!memcmp(w.der,reg.certs[j].der,w.size)) found++;
            assert(found==1);
            free(w.der);
        }
    }
    printf("%s: wire %zu, staged DER %zu, result %d, selected %zu\n",name,wire,staged,result,result?0:reg.count);
done:
    free(own.der);
    pki_est_free(&lite);
    pki_est_free(&reg);
    return 0;
}
int main(int argc,char **argv)
{
    assert(argc==2);
    const char *d=argv[1];
    verify(d,"overlap.cms.b64",4,"lite-twin.der");
    verify(d,"cutover.cms.b64",2,"lite-twin.der");
    verify(d,"missing-role.cms.b64",-1,"lite-twin.der");
    verify(d,"wrong-branch.cms.b64",-1,"lite-twin.der");
    verify(d,"overlap.cms.b64",-1,"wrong-twin.der");
}
