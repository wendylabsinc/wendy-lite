"""Compile the actual public caller and actor pickup, not a copied model."""
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
start = source.index("static struct topology_query *topology_query;")
end = source.index('static const char *TAG = "wendy_net_peer";', start)
Path(sys.argv[2]).write_text(source[start:end])
