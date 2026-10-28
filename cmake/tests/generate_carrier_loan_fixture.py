#!/usr/bin/env python3
"""Extract the actual actor boundary callbacks for a positive signing-loan test."""
from pathlib import Path
import re
import sys
project = Path(__file__).resolve().parents[2]
def function(source, name):
    match = re.search(r'(?m)^static[^\n]*\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', source)
    assert match, name
    at = source.index('{', match.start())
    depth, end = 1, at + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'
parts = []
for path, names in [('peer.c', ['carrier_read', 'carrier_write']),
                    ('router_session.c', ['describe'])]:
    source = (project / 'components/wendy_net_peer/src' / path).read_text()
    parts.extend(function(source, name) for name in names)
Path(sys.argv[1]).write_text('\n'.join(parts))
