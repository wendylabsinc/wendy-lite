/* Positive host observability only: no RNG or authentication replacement. */
#include <mbedtls/platform_util.h>
static bool cv_trace_started;
#if defined(WENDY_TLS_CV_TRACE)
extern unsigned long wendy_test_cv_signs,wendy_test_cv_fragments,wendy_test_cv_hashed;
extern unsigned long wendy_test_cv_releases,wendy_test_cv_wants,wendy_test_cv_max_fragment;
extern void *wendy_test_cv_allocation;
static bool cv_trace_own_key;
static bool cv_trace_cancelled;
static bool cv_trace_budgeted;
static unsigned cv_trace_zero_frees;
static void *cv_trace_allocate(size_t count,size_t size)
{return cv_trace_budgeted ? wendy_net_memory_scoped_calloc(count,size):calloc(count,size);}
static void cv_trace_release(void *pointer)
{
    if(pointer && pointer==wendy_test_cv_allocation){
        for(unsigned i=0;i<3317;i++)assert(((unsigned char*)pointer)[i]==0);
        cv_trace_zero_frees++;
    }
    if(cv_trace_budgeted)wendy_net_memory_scoped_free(pointer);else free(pointer);
}
static void cv_trace_check(void)
{
    unsigned long expected=cv_trace_own_key ? 1:0;
    if(getenv("WENDY_TLS_NORMAL_REPEAT"))expected*=strtoul(getenv("WENDY_TLS_NORMAL_REPEAT"),NULL,10);
    assert(wendy_test_cv_signs==expected && wendy_test_cv_releases==expected);
    assert(cv_trace_zero_frees==expected && !wendy_test_cv_allocation);
    if(expected){
        assert(wendy_test_cv_max_fragment<=2048);
        if(cv_trace_cancelled){
            assert(wendy_test_cv_hashed>0 && wendy_test_cv_hashed<=3317);
            assert(wendy_test_cv_wants>0);
        }else{
            assert(wendy_test_cv_fragments==2*expected);
            assert(wendy_test_cv_hashed==3317*expected);
        }
    }
    fprintf(stderr,"CV_TRACE signs=%lu fragments=%lu hashed=%lu max_fragment=%lu wants=%lu zero_frees=%u PASS\n",
        wendy_test_cv_signs,wendy_test_cv_fragments,wendy_test_cv_hashed,
        wendy_test_cv_max_fragment,wendy_test_cv_wants,cv_trace_zero_frees);
}
#endif
static void cv_trace_begin(const char *key_path,bool budgeted)
{
#if defined(WENDY_TLS_CV_TRACE)
    if(!getenv("WENDY_TLS_OWN_MLDSA65") || cv_trace_started)return;
    size_t length;unsigned char *key=load(key_path,&length);
    static const unsigned char prefix[]={0x30,0x34,0x02,0x01,0x00,0x30,0x0b,
        0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12,0x04,0x22,0x80,0x20};
    cv_trace_own_key=length==54 && !memcmp(key,prefix,sizeof prefix);
    cv_trace_budgeted=budgeted;
    mbedtls_platform_zeroize(key,length);free(key);
    assert(!mbedtls_platform_set_calloc_free(cv_trace_allocate,cv_trace_release));
    cv_trace_started=true;assert(!atexit(cv_trace_check));
#else
    (void)key_path;
    (void)budgeted;
    (void)cv_trace_started;
#endif
}
