import json
import subprocess
import sys

binary = sys.argv[1]
def run(mode):
    p = subprocess.run([binary, mode], capture_output=True, text=True, check=True)
    records = [json.loads(x.split('WN_CLOCK_OBS ', 1)[1]) for x in p.stderr.splitlines() if 'WN_CLOCK_OBS ' in x]
    assert not any(x in p.stderr for x in ['http://', 'https://', 'nonce', 'PRIVATE KEY'])
    assert all(len(json.dumps(x, separators=(',', ':'))) < 768 for x in records)
    return records
b, = run('boot')
assert b['event'] == 'boot' and b['certificate_base_seconds'] == 0 and not b['anchor_available']
assert b['boot_uncertain'] and not b['fresh_tsa'] and not b['tsa_verified_this_boot']
assert b['raw_utc_before_us'] == b['raw_utc_after_us'] == 100000123
delayed, = run('delayed')
assert delayed['event'] == 'boot' and delayed['raw_utc_before_us'] == delayed['raw_utc_after_us'] == 100000123
assert delayed['monotonic_us'] == 3000000 and delayed['emitted_monotonic_us'] == 303000000
assert delayed['certificate_base_seconds'] == 0 and not delayed['anchor_available']
assert delayed['boot_uncertain'] and not delayed['fresh_tsa'] and not delayed['tsa_verified_this_boot']
assert len(run('ready_first')) == len(run('publication')) == 1
r, = run('remote')
assert r['event'] == 'first_remote_mesh_admission' and r['certificate_base_seconds'] == 202
assert r['anchor_seconds'] == 200 and r['anchor_monotonic_us'] == 1000000 and r['anchor_available']
assert r['boot_uncertain'] and not r['fresh_tsa'] and not r['tsa_verified_this_boot']
z, = run('floor_zero')
assert z['anchor_available'] and z['anchor_seconds'] == 200 and z['certificate_base_seconds'] == 202
n, = run('no_proof')
assert not n['boot_uncertain'] and not n['fresh_tsa'] and not n['tsa_verified_this_boot']
d, = run('direct')
assert d['event'] == 'direct_https_time_apply' and d['source'] == 'direct_https_signed_time'
assert d['status'] == 'applied' and d['fresh_tsa'] and d['tsa_verified_this_boot'] and not d['boot_uncertain']
assert d['certificate_base_seconds'] == 300
s, = run('sufficient')
assert s['status'] == 'already_sufficient'
a, = run('stale')
assert not a['fresh_tsa'] and a['tsa_verified_this_boot'] and not a['boot_uncertain']
g, = run('generation')
assert not g['fresh_tsa'] and g['tsa_verified_this_boot']
x, = run('reset')
assert not x['anchor_available'] and not x['fresh_tsa'] and x['tsa_verified_this_boot'] and x['boot_uncertain']
e, = run('errors')
assert e['raw_utc_before_us'] is None and e['raw_utc_after_us'] is None and e['raw_utc_read_error']
f, = run('race')
assert not f['snapshot_available'] and f['fresh_tsa'] is None and f['anchor_available']
assert len(run('bounded')) == 16
latches = run('latches')
assert [x['event'] for x in latches] == ['boot', 'first_remote_mesh_admission', 'direct_https_time_apply']
assert latches[-1]['tsa_verified_this_boot'] and not latches[-1]['fresh_tsa']
o, = run('overflow')
assert o['raw_utc_before_us'] is None and o['raw_utc_after_us'] is None and o['raw_utc_read_error']
assert not run('concurrent')
sizes = json.loads(subprocess.check_output([binary, 'sizes'], text=True))
assert sizes['observer_atomic_payload'] == 72 and sizes['boot_record'] <= 64
assert sizes['observer_static_declared'] - 79 <= 100
print('observer schema, truthful freshness/ever, reset, read errors, bounded races/events, immutable input PASS', sizes)
