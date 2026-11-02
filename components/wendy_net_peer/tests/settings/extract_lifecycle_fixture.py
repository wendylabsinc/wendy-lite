from pathlib import Path
import sys
source=Path(sys.argv[1]).read_text()
a=source.index("static void lifecycle_poll(void)\n{")
b=source.index("\nesp_err_t wendy_net_peer_start(void)",a)
Path(sys.argv[2]).write_text(source[a:b]+"\n")
