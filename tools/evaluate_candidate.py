#!/usr/bin/env python3
"""Evaluate a teacher-supplied source file as an unknown patch, with NO engine changes.

Usage: python3 tools/evaluate_candidate.py --target cjsonreal --source candidates/newpatch.c
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

# Executed by name from project's tools/ directory.
from blind_patch_test import ROOT, isolated_run


def main() -> int:
    p=argparse.ArgumentParser(description='Evaluate an unseen C source using the existing verified target oracle')
    p.add_argument('--target',choices=['frame','cjsonreal'],required=True)
    p.add_argument('--source',required=True,help='Path to candidate C source inside the project directory')
    p.add_argument('--minimize',action='store_true')
    ns=p.parse_args()
    source=(ROOT/ns.source).resolve()
    if not source.is_file() or not source.is_relative_to(ROOT):
        p.error('Candidate must be a C file within the repository checkout')
    if source.suffix!='.c':
        p.error('Candidate must be a .c file')
    cfg=json.loads((ROOT/'configs'/f'{ns.target}-correct.json').read_text(encoding='utf-8'))
    digest=hashlib.sha256(source.read_bytes()).hexdigest()[:14]
    candidate_id=f'candidate_{digest}'
    cfg['name']=candidate_id
    cfg['patch']=source.relative_to(ROOT).as_posix()
    location=ROOT/'artifacts'/'candidate-evaluations'/candidate_id
    location.mkdir(parents=True,exist_ok=True)
    config_rel=(location/'input.json').relative_to(ROOT).as_posix()
    (location/'input.json').write_text(json.dumps(cfg,indent=2)+'\n',encoding='utf-8')
    output_rel=(location/'run').relative_to(ROOT).as_posix()
    (location/'run').mkdir(parents=True,exist_ok=True)
    print('Evaluating',ns.target,'candidate',source.relative_to(ROOT))
    code,output=isolated_run(config_rel,output_rel,ns.minimize)
    print(output)
    report=location/'run'/'report.json'
    if not report.exists():
        print('No report was produced: Docker or build infrastructure failed',file=sys.stderr)
        return 30
    parsed=json.loads(report.read_text(encoding='utf-8'))
    result=parsed['scenarios'][0]
    print('Security:',result['security_status'])
    print('Functionality:',result['functionality_status'])
    print('Complete:',result['analysis_complete'])
    print('Verdict:',result['status'],result['exit_code'])
    print('Evidence:',report.relative_to(ROOT))
    if code != result['exit_code']:
        print('Warning: runner exit status differs from report',file=sys.stderr)
        return 30
    return result['exit_code']


if __name__=='__main__':
    sys.exit(main())
