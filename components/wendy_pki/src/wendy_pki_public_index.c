#include "wendy_pki_public_index.h"
#include "wendy_pki_mesh.h"
#include "wendy_conf.h"
#include <stdatomic.h>

static atomic_uint certificate_epoch=1;
uint32_t pki_public_certificate_epoch(void)
{return atomic_load(&certificate_epoch);}
void pki_public_certificate_changed(void)
{atomic_fetch_add(&certificate_epoch,1);}
bool wendy_pki_mesh_public_index_current(const struct wendy_pki_mesh_public_index *index,
    const struct wendy_pki_mesh_identity *clock)
{
    return index && clock && index->count && index->count<=8 &&
        index->config_generation==clock->config_generation &&
        index->certificate_epoch==pki_public_certificate_epoch() &&
        !wendy_pki_reset_in_progress() &&
        wendy_conf_snapshot_current(index->config_generation);
}
