/* SPDX-License-Identifier: Apache-2.0 */
#include "certificate_read.h"
#include "wendy_net_alloc.h"
#include "wendy_pki_work.h"
#include <stdatomic.h>
#include <string.h>

struct wncd_job {
    atomic_uint references;
    atomic_bool done;
    struct wendy_pki_mesh_identity clock;
    uint32_t certificate_epoch;
    uint8_t hash[32],bytes[1024];
    size_t offset,total,expected_total;
    int result;
};
static void job_release(struct wncd_job *job)
{if(job && atomic_fetch_sub(&job->references,1)==1)wendy_net_free(job);}
static void execute(void *context)
{
    struct wncd_job *job=context;
    job->result=wendy_pki_mesh_local_part_snapshot(&job->clock,job->certificate_epoch,
        job->hash,job->offset,job->bytes,&job->total);
    if(job->result>0){
        size_t wanted=job->expected_total-job->offset;if(wanted>1024)wanted=1024;
        if(job->total!=job->expected_total || job->result!=(int)wanted)job->result=-1;
    }
    atomic_store(&job->done,true);job_release(job);
}
static bool same(const struct wncd_reader *reader,uint64_t owner,bool catalog,
    const uint8_t hash[32],size_t offset)
{
    return reader->owner==owner && reader->catalog==catalog &&
        reader->offset==offset && !memcmp(reader->hash,hash,32);
}
int wncd_read(struct wncd_reader *reader,uint64_t owner,bool catalog,
    uint64_t generation,uint32_t certificate_epoch,const uint8_t hash[32],
    size_t offset,size_t expected_total,uint8_t out[1024],size_t *total)
{
    if(!reader || !hash || !total || !owner || !generation ||
       !expected_total || expected_total>65536 || offset>=expected_total || offset%1024)return -1;
    *total=0;
    if(reader->phase==WNCD_IDLE){
        reader->owner=owner;reader->catalog=catalog;reader->generation=generation;
        reader->certificate_epoch=certificate_epoch;reader->offset=offset;reader->total=expected_total;
        memcpy(reader->hash,hash,32);reader->phase=WNCD_REQUESTED;
        return -2;
    }
    if(!same(reader,owner,catalog,hash,offset) || reader->phase!=WNCD_READY)return -2;
    if(reader->generation!=generation || reader->certificate_epoch!=certificate_epoch ||
       reader->total!=expected_total)return -1;
    *total=reader->total;
    if(reader->result>0 && out)memcpy(out,reader->bytes,(size_t)reader->result);
    return reader->result;
}
void wncd_release(struct wncd_reader *reader,uint64_t owner,bool catalog,
    const uint8_t hash[32],size_t offset)
{
    if(reader && hash && reader->phase!=WNCD_IDLE && same(reader,owner,catalog,hash,offset))
        reader->phase=WNCD_CONSUMED;
}
void wncd_close(struct wncd_reader *reader)
{
    if(!reader)return;
    struct wncd_job *job=reader->job;
    *reader=(struct wncd_reader){0};job_release(job);
}
void wncd_cancel(struct wncd_reader *reader,uint64_t owner)
{if(reader && reader->phase!=WNCD_IDLE && reader->owner==owner)wncd_close(reader);}
int64_t wncd_deadline(const struct wncd_reader *reader)
{
    if(!reader)return INT64_MAX;
    return reader->phase==WNCD_REQUESTED ? reader->retry_at:INT64_MAX;
}
int wncd_poll(struct wncd_reader *reader,const struct wendy_pki_mesh_identity *clock,
    bool current,int64_t now)
{
    if(!reader || reader->phase==WNCD_IDLE)return 0;
    if(reader->phase==WNCD_CONSUMED){wncd_close(reader);return 1;}
    struct wncd_job *job=reader->job;
    if(reader->phase==WNCD_RUNNING){
        if(!atomic_load(&job->done))return 0;
        if(current && job->result==-2){
            reader->job=NULL;job_release(job);reader->phase=WNCD_REQUESTED;
            reader->retry_at=now+50000;return 1;
        }
        reader->result=current ? job->result:-1;
        reader->bytes=reader->result>0 ? job->bytes:NULL;
        reader->phase=WNCD_READY;return 1;
    }
    if(reader->phase!=WNCD_REQUESTED || now<reader->retry_at)return 0;
    if(!clock || !current){reader->result=-1;reader->phase=WNCD_READY;return 1;}
    if(!wendy_pki_work_idle()){reader->retry_at=now+50000;return 0;}
    job=wendy_net_calloc(1,sizeof *job);
    if(!job){reader->retry_at=now+50000;return 0;}
    atomic_init(&job->references,2);atomic_init(&job->done,false);
    job->clock=*clock;job->offset=reader->offset;job->expected_total=reader->total;
    job->certificate_epoch=reader->certificate_epoch;
    memcpy(job->hash,reader->hash,32);
    if(!wendy_pki_work_submit(execute,job)){
        atomic_store(&job->references,1);job_release(job);reader->retry_at=now+50000;return 0;
    }
    reader->job=job;reader->phase=WNCD_RUNNING;return 1;
}
