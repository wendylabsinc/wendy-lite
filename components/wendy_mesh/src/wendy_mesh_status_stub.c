#include "sdkconfig.h"
#include "wendy_mesh_status.h"
#include <string.h>

#if !CONFIG_WENDY_MESH_LEAF
void wendy_mesh_get_snapshot(struct wendy_mesh_snapshot *snapshot)
{
    if (snapshot) {
        memset(snapshot, 0, sizeof *snapshot);
        snapshot->phase = WENDY_MESH_DISABLED;
    }
}
#endif
