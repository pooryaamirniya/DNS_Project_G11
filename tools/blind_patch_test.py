#!/usr/bin/env python3
"""Generate and evaluate unknown patch variants of both declared targets.

The verification engine NEVER receives scenario labels/expected verdicts as inputs.
Oracle and attack cases are cloned from independently approved existing configs.
All malicious code executes in a locked-down Docker container, not in the host.

Usage (from project root): python3 tools/blind_patch_test.py
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
PATCHGUARD_IMAGE = 'patchguard-security-project:local'
CJSON_GUARD = re.compile(r'if\s*\(\s*object->valuestring\s*==\s*NULL\s*\|\|\s*valuestring\s*==\s*NULL\s*\)')
FRAME_GUARD = re.compile(r'if\s*\(\s*length\s*>=\s*sizeof\s+normalized\s*\)')


def rewrite_once(source: str, pattern: re.Pattern[str], replacement: str, description: str) -> str:
    updated, count = pattern.subn(lambda _: replacement, source, count=1)
    if count != 1:
        raise RuntimeError(f'{description}: expected exactly one matching guard, got {count}')
    return updated


def frame_patch(source: str, mode: str) -> str:
    if mode == 'pass':
        expr = 'if (length > ((sizeof normalized) - 1))'
        return rewrite_once(source, FRAME_GUARD, expr, 'frame good')
    if mode == 'incomplete':
        expr = 'if (length >= sizeof normalized && length != 24)'
        return rewrite_once(source, FRAME_GUARD, expr, 'frame bypass')
    if mode == 'regression':
        expr = 'if (length >= sizeof normalized || length == 2)'
        return rewrite_once(source, FRAME_GUARD, expr, 'frame regression')
    if mode == 'new_issue':
        # A DIFFERENT vulnerability class from the original stack overwrite.
        # The injected bug is a test fixture, not a claim about upstream software.
        expr = '''if (length == 24) {
        char *fresh = malloc(4);
        if (fresh == NULL) return 3;
        free(fresh);
        volatile char observed = fresh[0];
        (void)observed;
    }
    if (length >= sizeof normalized)'''
        return rewrite_once(source, FRAME_GUARD, expr, 'frame new security issue')
    if mode in ('inconclusive','build_error'):
        return frame_patch(source, 'pass')
    raise ValueError(f'unknown frame mode: {mode}')


def cjson_patch(source: str, mode: str) -> str:
    if mode == 'pass':
        expr = 'if ((object->valuestring == NULL) || (valuestring == NULL))'
    elif mode == 'incomplete':
        expr = ('if ((object->valuestring == NULL) || '
                '(valuestring == NULL && strlen(object->valuestring) == 5))')
    elif mode == 'regression':
        expr = ('if ((object->valuestring == NULL) || (valuestring == NULL) || '
                '(valuestring != NULL && strlen(valuestring) == 5))')
    else:
        raise ValueError(f'unknown cJSON mode: {mode}')
    return rewrite_once(source, CJSON_GUARD, expr, 'cJSON candidate')


def setup_cases(directory: Path, seed: str) -> list[dict]:
    """Create candidates from source content, not from expected result identifiers."""
    specs = [
        ('frame','pass',0),
        ('frame','incomplete',10),
        ('frame','regression',20),
        ('frame','new_issue',10),
        ('frame','inconclusive',40),
        ('frame','build_error',30),
        ('cjsonreal','pass',0),
        ('cjsonreal','incomplete',10),
        ('cjsonreal','regression',20),
    ]
    created = []
    for number,(target,mode,expected) in enumerate(specs):
        baseline_path=ROOT/'configs'/f'{target}-correct.json'
        if not baseline_path.is_file():
            raise FileNotFoundError(f'Missing existing config: {baseline_path}')
        config=json.loads(baseline_path.read_text(encoding='utf-8'))
        source_path=ROOT/'targets'/target/'correct.c'
        if not source_path.is_file():
            raise FileNotFoundError(f'Missing existing corrected source: {source_path}')
        source=source_path.read_text(encoding='utf-8')
        token=hashlib.sha256(f'{seed}/{number}'.encode()).hexdigest()[:12]
        candidate_name=f'candidate_{token}'
        patch_rel=Path('artifacts')/'blind-patches'/'candidates'/(candidate_name+'.c')
        dest=ROOT/patch_rel
        dest.parent.mkdir(parents=True,exist_ok=True)
        patched=frame_patch(source,mode) if target=='frame' else cjson_patch(source,mode)
        dest.write_text(patched,encoding='utf-8')
        config['name']=candidate_name
        config['patch']=patch_rel.as_posix()
        if mode=='inconclusive':
            # Baseline must not crash on one declared security case: impossible
            # to claim a complete security verdict => 40. Regression corpus
            # still checks all other known crashes.
            config['attacks']=[{
                'id':'no-verified-baseline-crash',
                'text':'MSG:ok\n',
                'category':'deliberately unconfirmed baseline precondition',
                'expected':{'exit_code':0,'stdout':'OK:ok\n'}
            }]
        if mode=='build_error':
            config['patch'] = f'artifacts/blind-patches/candidates/missing_{token}.c'
        cfg_rel=Path('artifacts')/'blind-patches'/'configs'/(candidate_name+'.json')
        config_path=ROOT/cfg_rel
        config_path.parent.mkdir(parents=True,exist_ok=True)
        config_path.write_text(json.dumps(config,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        created.append({'candidate':candidate_name,'target':target,
                        'expected':expected,'mode':mode,
                        'config':cfg_rel.as_posix(),'source':config['patch']})
    return created


def isolated_run(config_rel: str, out_rel: str, minimize: bool = False) -> tuple[int,str]:
    args=['docker','run','--rm', '--network','none', '--cap-drop','ALL',
          '--security-opt','no-new-privileges','--pids-limit','128',
          '--memory','768m', '--cpus','2', '--read-only',
          '--tmpfs','/tmp:rw,nosuid,nodev,size=64m',
          '--user',f'{os.getuid()}:{os.getgid()}',
          '-v',f'{ROOT}:/work:rw',PATCHGUARD_IMAGE,
          '--config',config_rel,'--out',out_rel]
    if not minimize:
        args.append('--skip-minimize')
    proc=subprocess.run(args,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                        text=True,timeout=180)
    return proc.returncode,proc.stdout


def main() -> int:
    parser=argparse.ArgumentParser(description='Test unseen source changes without modifying PatchGuard code')
    parser.add_argument('--prepare-only',action='store_true',help='Generate fixture files and manifest only')
    parser.add_argument('--minimize',action='store_true',help='Also minimize crashes; more time-consuming')
    args=parser.parse_args()
    if not (ROOT/'patchguard'/'cli.py').is_file():
        parser.error('Run inside the PatchGuard_Project1 folder')
    # Commit this unique suite (manifest can be shared and rerun, generated content is untracked).
    run_id=secrets.token_hex(4)
    print('Preparing blind source variants; run:',run_id,flush=True)
    cases=setup_cases(ROOT/'artifacts'/'blind-patches',run_id)
    results_root=ROOT/'artifacts'/'blind-patches'
    manifest={'suite_id':run_id,'cases':cases,'note':
      'Expected classifications are ONLY in this harness, not in PatchGuard input configs.'}
    manifest_file=results_root/'manifest.json'
    manifest_file.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print('Wrote:',manifest_file.relative_to(ROOT),flush=True)
    if args.prepare_only:
        return 0
    outcome=[]
    for index,case in enumerate(cases,1):
        label=case['candidate']
        out_rel=f'artifacts/blind-patches/results/{label}'
        (ROOT/out_rel).mkdir(parents=True,exist_ok=True)
        print(f'[{index}/{len(cases)}] {case["target"]} candidate {label} ...',flush=True)
        try:
            process_status,log=isolated_run(case['config'],out_rel,args.minimize)
            report_path=ROOT/out_rel/'report.json'
            if not report_path.is_file():
                actual='missing-report'
            else:
                report=json.loads(report_path.read_text(encoding='utf-8'))
                actual=report['scenarios'][0]['exit_code']
            okay=(actual==case['expected'] and process_status==case['expected'])
            print(f'  expected={case["expected"]} observed={actual}; '
                  f'process={process_status} => {"PASS" if okay else "FAIL"}',flush=True)
            if not okay:
                print('  Last output lines:\n'+'\n'.join(log.splitlines()[-20:]),flush=True)
        except Exception as exc:
            actual=f'exception: {type(exc).__name__}: {exc}'
            okay=False
            print('  FAIL:',actual,flush=True)
        outcome.append({'candidate':label,'target':case['target'],
                        'expected':case['expected'],'observed':actual,'passed':okay})
    summary={'suite_id':run_id,'passed':sum(int(r['passed']) for r in outcome),
             'total':len(outcome),'cases':outcome}
    (results_root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(f'Blind patch matrix: {summary["passed"]}/{summary["total"]} passed')
    print('Summary: artifacts/blind-patches/summary.json')
    return 0 if summary['passed']==summary['total'] else 1


if __name__=='__main__':
    sys.exit(main())
