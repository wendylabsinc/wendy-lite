#include "netif_effect.h"
#include <limits.h>
enum {RETRY_US=10000};
void wnne_init(struct wnne_effect *effect,enum wnne_target applied)
{
    *effect=(struct wnne_effect){.desired=applied,.applied=applied};
    atomic_init(&effect->done,false);
}
void wnne_desire(struct wnne_effect *effect,enum wnne_target target)
{effect->desired=target;}
bool wnne_next(struct wnne_effect *effect,int64_t now)
{
    if(effect->pending){
        if(!atomic_load_explicit(&effect->done,memory_order_acquire))return false;
        effect->pending=false;
        if(!effect->result)effect->applied=effect->submitted;
        else effect->retry_at=now+RETRY_US;
    }
    if(effect->applied==effect->desired || now<effect->retry_at)return false;
    effect->submitted=effect->desired;
    atomic_store_explicit(&effect->done,false,memory_order_relaxed);
    effect->pending=true;return true;
}
void wnne_submitted(struct wnne_effect *effect,bool accepted,int64_t now)
{
    if(!accepted){effect->pending=false;effect->retry_at=now+RETRY_US;}
}
void wnne_complete(struct wnne_effect *effect,int result)
{
    effect->result=result;
    atomic_store_explicit(&effect->done,true,memory_order_release);
}
bool wnne_idle(const struct wnne_effect *effect)
{return !effect->pending && effect->applied==effect->desired;}
int64_t wnne_deadline(const struct wnne_effect *effect)
{
    if(effect->pending || effect->applied==effect->desired)return INT64_MAX;
    return effect->retry_at;
}
