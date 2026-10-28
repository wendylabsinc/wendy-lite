#!/usr/bin/env python3
"""Run normal native Lite TLS fixtures against the actual WendyOS issuer helpers.

Go overlays add temporary test files without editing either WendyOS sources or
its module. Fixture certificates are local generated test identities only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True)
    parser.add_argument('--wendyos-root', type=Path, required=True, help='WendyOS/go module root')
    parser.add_argument('--driver', type=Path, required=True)
    args = parser.parse_args()
    module = args.wendyos_root.resolve()
    if (module / 'go/internal/agent/bleprovider').is_dir():
        module = module / 'go'
    package = module / 'internal/agent/bleprovider'
    helper_path = package / 'tls_issuers_linux.go'
    fixture_path = package / 'tls_issuers_linux_test.go'
    helper = helper_path.read_text()
    fixture = fixture_path.read_text()
    fixture = fixture[fixture.index('// deviceKey'):fixture.index('// airPath')]
    # Keep this genuine three-issuer fixture below Lite's existing16KiB trust
    # limit. Certificate padding changes size only, not anchors or TLS policy.
    assert '[]int{7050, 6350, 5050}' in fixture
    fixture = fixture.replace('[]int{7050, 6350, 5050}', '[]int{1200, 1100, 1000}')
    fixture = fixture.replace('return credentials', 'liteIssuerRoots[credentials]=chain\nreturn credentials')
    for before, after in [('ecdsaDeviceKey', 'liteIssuerECDSA'),
                          ('mldsaDeviceKey', 'liteIssuerMLDSA'),
                          ('deviceKey', 'liteIssuerDeviceKey'),
                          ('issuerCredentials', 'liteIssuerCredentials')]:
        fixture = fixture.replace(before, after)
    imports = 'bytes crypto crypto/ecdsa crypto/elliptic crypto/mldsa crypto/rand crypto/x509 crypto/x509/pkix encoding/asn1 encoding/pem math/big net/url testing time'.split()
    header = 'package bleprovider\nimport (\n' + ''.join('"' + item + '"\n' for item in imports)
    header += '"github.com/wendylabsinc/wendy/go/internal/agent/localmesh"\n"github.com/wendylabsinc/wendy/go/internal/shared/meshid"\n)\n'
    header += 'var liteIssuerRoots=map[*localmesh.Credentials]string{}\n'
    host_os = subprocess.check_output([args.go, 'env', 'GOOS'], text=True).strip()
    with tempfile.TemporaryDirectory(prefix='lite-issuer-wos-') as temporary:
        temporary = Path(temporary)
        replacements = {}
        if host_os != 'linux':
            # Linux already compiles the canonical helper directly. On Darwin,
            # compile its exact body under a neutral overlay filename instead.
            target = temporary / 'issuer_helper.go'
            target.write_text(helper.replace('//go:build linux\n', '', 1))
            replacements[str(package / 'lite_issuer_helper_overlay.go')] = str(target)
        target = temporary / 'issuer_fixture_test.go'
        target.write_text(header + fixture)
        replacements[str(package / 'lite_issuer_fixture_overlay_test.go')] = str(target)
        target = temporary / 'issuer_interop_test.go'
        target.write_text(Path(__file__).with_name('issuer_interop_wos_test.go.in').read_text())
        replacements[str(package / 'lite_issuer_interop_overlay_test.go')] = str(target)
        overlay = temporary / 'overlay.json'
        overlay.write_text(json.dumps({'Replace': replacements}))
        print('WendyOS issuer helper SHA256=' + hashlib.sha256(helper.encode()).hexdigest(), flush=True)
        environment = dict(os.environ, WENDY_LITE_ISSUER_DRIVER=str(args.driver.resolve()))
        subprocess.run([args.go, 'test', '-timeout', '90s', '-count=1', '-overlay=' + str(overlay),
                        '-run', '^TestLiteIssuerInteropNormal$', '-v', './internal/agent/bleprovider'],
                       cwd=module, env=environment, check=True)


if __name__ == '__main__':
    run()
