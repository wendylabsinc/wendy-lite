"""Exercise the actual conservative production ownership probe on the host."""
from pathlib import Path
import os, subprocess, tempfile
root=Path(__file__).resolve().parent.parent
source=(root/'src/wendy_ble_mesh.c').read_text()
probe=source[source.index('bool wble_mesh_uses_connection(uint16_t handle)'):]
assert probe.rstrip().endswith('}')
fixture=r'''
#include <assert.h>
#include <stdint.h>
#include "mesh_report_lifetime.h"
#define CHANNELS 3
struct wble_mesh_pipe { uint16_t handle; bool pending,closing,time; };
static struct wble_mesh_pipe *pipes[CHANNELS];
static struct wble_report_lifetime report_lifetime;
static bool lock_available=true;
static unsigned unlocks;
static bool trylock(void){return lock_available;}
static void unlock(void){unlocks++;}
'''+probe+r'''
int main(void){
 assert(wble_mesh_uses_connection(1)); /* unknown/OFF conservatively retained */
 wble_report_open(&report_lifetime);
 assert(!wble_mesh_uses_connection(1));assert(wble_report_drained(&report_lifetime));
 struct wble_mesh_pipe p={.handle=1,.pending=true};pipes[0]=&p;
 assert(wble_mesh_uses_connection(1)); /* accepted, before authentication */
 p.pending=false;p.closing=true;assert(wble_mesh_uses_connection(1));
 p.time=true;assert(wble_mesh_uses_connection(1)); /* signed-time also claims */
 assert(!wble_mesh_uses_connection(2));
 lock_available=false;assert(wble_mesh_uses_connection(2));
 assert(wble_report_drained(&report_lifetime));lock_available=true;
 pipes[0]=0;assert(!wble_mesh_uses_connection(1));
 wble_report_close(&report_lifetime);assert(wble_mesh_uses_connection(1));
 assert(wble_report_drained(&report_lifetime));assert(unlocks==6);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
 path=Path(tmp);(path/'test.c').write_text(fixture)
 subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(root/'src'),str(path/'test.c'),'-o',str(path/'test')],check=True)
 subprocess.run([str(path/'test')],check=True)
print('Actual mesh ownership probe preserves pending/closing/time claims and conservatively retains unknown/contended lifetime')
