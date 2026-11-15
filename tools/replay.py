"""Independently rebuild and replay a minimized sanitizer reproducer in an isolated VM/container."""
import argparse
import json
from pathlib import Path
import sys
from patchguard.cli import ROOT, crash_consensus, trials
from patchguard.runner import build, sha256


def main():
    arg=argparse.ArgumentParser()
    arg.add_argument('manifest', help='Path to repro/.../manifest.json')
    arg.add_argument('--allow-local',action='store_true',help='Only in an isolated/disposable VM')
    options=arg.parse_args()
    if not options.allow_local and __import__('os').environ.get('PATCHGUARD_ISOLATED')!='1':
        raise SystemExit('Run inside Docker or use --allow-local ONLY in an isolated VM')
    manifest_path=Path(options.manifest).resolve()
    meta=json.loads(manifest_path.read_text())
    src=ROOT/meta['source']
    if not src.exists() or sha256(src)!=meta['source_sha256']:
        raise SystemExit('Source not present or source SHA-256 differs')
    cfg_path=ROOT/'configs'/(meta['scenario']+'.json')
    cfg=json.loads(cfg_path.read_text())
    binary=ROOT/'artifacts'/'replay'/meta['scenario']/ 'base-sanitized'
    result=build(ROOT,meta['source'],cfg['target'],'sanitized',binary,version='base')
    if result['returncode']:
        raise SystemExit('Rebuild failed: '+result['stderr'])
    data=(manifest_path.parent/'minimized.bin').read_bytes()
    attempts=trials(binary,data,3,mode=meta.get('execution',{}).get('mode','stdin'))
    state,finding=crash_consensus(attempts)
    okay=(state=='confirmed' and finding['error_type']==meta['error_type'] and
          finding['function']==meta['reference_function'])
    print('Replayed:',meta['scenario'],meta['case'],'result:',state)
    print('Error:',finding['error_type'],'function:',finding['function'])
    print('Match original finding:',okay)
    print('Rebuilt binary SHA-256:',sha256(binary))
    print('Original binary SHA-256:',meta['sanitized_binary_sha256'])
    return 0 if okay else 1

if __name__=='__main__':
    sys.exit(main())
