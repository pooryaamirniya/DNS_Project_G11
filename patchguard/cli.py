"""Command-line interface for evidence-first patch validation."""
import argparse
import hashlib
from collections import Counter
import json
import os
from pathlib import Path
import platform
import sys
import traceback

from .runner import build, command, run, sha256
from .detection import detect, expected_behavior, signature
from .minimize import minimize_crash
from .hardening import inspect, compare
from .correlation import correlate

ROOT = Path(__file__).resolve().parent.parent
STATUS_TEXT = {0:'PASS',10:'VULN_REMAINS_OR_NEW_ISSUE',20:'FUNC_REGRESSION',
               30:'BUILD_OR_CONFIG_ERROR',40:'INCONCLUSIVE'}


def input_bytes(item):
    if 'text' in item:
        return item['text'].encode('utf-8')
    if 'hex' in item:
        return bytes.fromhex(item['hex'])
    raise ValueError('test case requires text or hex')


def independent_oracle(case):
    expected = case['expected']
    return {'exit_code':expected['exit_code'], 'stdout':expected['stdout']}


def trials(binary, payload, n=3, mode="stdin"):
    sample=[]
    for _ in range(n):
        entry=run(binary, payload, mode=mode)
        sample.append({'process':entry, 'finding':detect(entry)})
    return sample


def crash_consensus(attempts):
    signatures=[signature(t['finding']) for t in attempts]
    if all(x is not None and x == signatures[0] for x in signatures):
        return 'confirmed',attempts[0]['finding']
    if any(x is not None for x in signatures) or any(t['finding']['mechanism'] != 'none' for t in attempts):
        return 'inconclusive',next((t['finding'] for t in attempts if t['finding']['confirmed']), attempts[0]['finding'])
    return 'absent',attempts[0]['finding']


def git_revision(root):
    p=command(['git','rev-parse','HEAD'],root)
    return p['stdout'].strip() if p['returncode']==0 else 'not-in-git'


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')


def load_persisted_regressions(root, target_id):
    """Include previously generated minimized reproducers in every subsequent evaluation."""
    folder = root / 'regressions' / target_id
    result=[]
    for metadata in sorted(folder.glob('*.json')):
        raw=json.loads(metadata.read_text(encoding='utf-8'))
        data_file=folder/(metadata.stem+'.bin')
        if not data_file.is_file():
            raise ValueError(f'regression input missing: {data_file}')
        result.append({'id':'reg-' + metadata.stem,'hex':data_file.read_bytes().hex(),
                       'category':'persisted_regression','persisted':True,
                       'expected':raw['patched_expected']})
    return result


def repro_bundle(root, out, scenario, target_id, case, payload, binary, orig_finding, buildlog, revision, mode="stdin"):
    """Creates source-linked reproducer and minimizes based on crash type AND function."""
    dest=out/'repro'/scenario/case['id']
    dest.mkdir(parents=True,exist_ok=True)
    mini,attempts=minimize_crash(binary,payload,orig_finding,mode=mode)
    (dest/'original.bin').write_bytes(payload)
    (dest/'minimized.bin').write_bytes(mini)
    replay=trials(binary,mini,3,mode=mode)
    consensus,_ = crash_consensus(replay)
    meta={'scenario':scenario,'case':case['id'],'original_length':len(payload),
          'minimized_length':len(mini),'minimization_executions':attempts,
          'error_type':orig_finding['error_type'],'reference_function':orig_finding['function'],
          'replay_consensus':consensus,'replays':replay,
          'git_commit':revision,'source':buildlog['source'],
          'source_sha256':sha256(root/buildlog['source']),
          'sanitized_binary_sha256':sha256(binary),
          'compile_command':buildlog['argv'],
          'environment':{'ASAN_OPTIONS':'detect_leaks=0:abort_on_error=1:print_stacktrace=1',
                         'UBSAN_OPTIONS':'print_stacktrace=1:halt_on_error=1'},
          'execution':{'argv':[str(binary)],'stdin_file':'minimized.bin',
                       'cwd':str(binary.parent),'mode':mode}}
    write_json(dest/'manifest.json',meta)
    # Regression input created from *observed* minimization, not hard-coded.
    reg=out/'regression'/scenario
    reg.mkdir(parents=True,exist_ok=True)
    (reg/(case['id']+'.bin')).write_bytes(mini)
    reg_record={'case_id':case['id'],
                        'base_expected_error_type':orig_finding['error_type'],
                        'base_expected_function':orig_finding['function'],
                        'patched_expected':case['expected']}
    write_json(reg/(case['id']+'.json'), reg_record)
    # Also add to the project's canonical regression suite. Version-control this
    # directory or restore it from a CI cache to retain results across clean jobs.
    canonical=root/'regressions'/target_id
    canonical.mkdir(parents=True,exist_ok=True)
    suffix=hashlib.sha256(mini).hexdigest()[:12]
    key=case['id']+'-'+suffix
    (canonical/(key+'.bin')).write_bytes(mini)
    write_json(canonical/(key+'.json'),reg_record)
    return {'path':str(dest.relative_to(out)),'minimized_size':len(mini),
            'replay_consensus':consensus,'regression_path':str((reg/(case['id']+'.bin')).relative_to(out))}


def evaluate(root, cfg, out, minimize=True):
    required={'name','base','patch','attacks','functional','target'}
    missing=required-set(cfg)
    if missing:
        raise ValueError(f'missing scenario fields: {sorted(missing)}')
    name=cfg['name']
    mode=cfg.get('input_mode','stdin')
    if mode not in ('stdin','argv','file'):
        raise ValueError('unsupported input_mode')
    build_dir=out/'build'/name
    build_records={}
    for ver in ('base','patch'):
        for kind in ('release','sanitized'):
            binary=build_dir / f'{ver}-{kind}'
            rec=build(root,cfg[ver],cfg['target'],kind,binary,version=ver)
            build_records[f'{ver}_{kind}']=rec
            if rec['returncode'] != 0:
                raise RuntimeError(f'Build failed {name} {ver} {kind}: {rec["stderr"]}')
    release0=build_dir/'base-release'
    release1=build_dir/'patch-release'
    san0=build_dir/'base-sanitized'
    san1=build_dir/'patch-sanitized'
    h0,h1=inspect(release0),inspect(release1)
    h_drops=compare(h0,h1)
    result={'scenario':name,'target':cfg['target']['name'],
            'versions':{'base':{'source':cfg['base'],'source_sha256':sha256(root/cfg['base'])},
                        'patch':{'source':cfg['patch'],'source_sha256':sha256(root/cfg['patch'])}},
            'builds':build_records,'hardening':{'base':h0,'patched':h1,'warnings':h_drops},
            'security_tests':[],'functional_tests':[],'generated_regressions':[]}
    status_security='fixed'
    status_function='pass'
    complete=True
    correlation=None
    revision=git_revision(root)
    first_error=None
    target_id=cfg['target']['id']
    all_attacks=cfg['attacks']+load_persisted_regressions(root,target_id)
    for case in all_attacks:
        payload=input_bytes(case)
        before=trials(san0,payload,3,mode=mode)
        after=trials(san1,payload,3,mode=mode)
        base_state,base_find=crash_consensus(before)
        patch_state,patch_find=crash_consensus(after)
        release_pre=run(release0,payload,mode=mode)
        release_post=run(release1,payload,mode=mode)
        expected=independent_oracle(case)
        item={'case_id':case['id'],'category':case.get('category','invalid'),
              'input_hex':payload.hex(),'expected_patched':expected,
              'base_sanitized':before,'patched_sanitized':after,
              'base_release':release_pre,'patched_release':release_post,
              'base_state':base_state,'patched_state':patch_state,
              'patched_oracle_pass':expected_behavior(release_post,expected)}
        if base_state == 'confirmed':
            if first_error is None:
                first_error=(base_find, release_pre, release_post)
            if minimize and not case.get('persisted'):
                bundle=repro_bundle(root,out,name,target_id,case,payload,san0,base_find,
                                    build_records['base_sanitized'],revision,mode=mode)
                item['reproducer']=bundle
                result['generated_regressions'].append(bundle)
                if bundle['replay_consensus'] != 'confirmed':
                    complete=False
        else:
            complete=False  # Missing/non-deterministic base precondition must never PASS.
        if patch_state == 'confirmed':
            status_security='incomplete' if (base_state=='confirmed' and signature(base_find)==signature(patch_find)) else 'new_issue'
        elif patch_state=='inconclusive' or base_state!='confirmed':
            if status_security=='fixed':
                status_security='inconclusive'
        elif not item['patched_oracle_pass']:
            # A crash or wrong exit without classified sanitizer evidence is inconclusive.
            complete=False
        result['security_tests'].append(item)
    for case in cfg['functional']:
        payload=input_bytes(case)
        expected=independent_oracle(case)
        before_release=run(release0,payload,mode=mode)
        after_release=run(release1,payload,mode=mode)
        before_san=run(san0,payload,mode=mode)
        after_san=run(san1,payload,mode=mode)
        b_ok=expected_behavior(before_release,expected)
        a_ok=expected_behavior(after_release,expected)
        item={'case_id':case['id'],'input_hex':payload.hex(),'reference':expected,
              'base_release':before_release,'patched_release':after_release,
              'base_sanitized':{'process':before_san,'finding':detect(before_san)},
              'patched_sanitized':{'process':after_san,'finding':detect(after_san)},
              'base_matches_reference':b_ok,'patched_matches_reference':a_ok}
        if b_ok and not a_ok:
            status_function='regression'
        if not b_ok:
            complete=False  # Independent reference must describe the baseline correctly.
        if detect(after_san)['confirmed']:
            status_security='new_issue'
        if detect(before_san)['confirmed'] and not detect(after_san)['confirmed']:
            # An unanticipated baseline bug is not enough to claim a patch regression.
            complete=False
        result['functional_tests'].append(item)
    if first_error is not None:
        finding,pre,post=first_error
        correlation=correlate(root,cfg['base'],cfg['patch'],finding,pre,post)
    else:
        correlation={'strength':'unknown','reason':'no confirmed base finding'}
    result['correlation']=correlation
    # Hardening weakening is an explicit warning, not fabricated test incompleteness.
    result['security_status']=status_security
    result['functionality_status']=status_function
    result['analysis_complete']=complete
    errors=[]
    if not complete or status_security=='inconclusive':
        errors.append(40)
    if status_function=='regression':
        errors.append(20)
    if status_security in ('incomplete','new_issue'):
        errors.append(10)
    result['exit_code']=next((c for c in (40,20,10,30,0) if c in errors),0)
    result['status']=STATUS_TEXT[result['exit_code']]
    return result


def markdown_report(report):
    lines=['# PatchGuard Verification Report', '',
           f"Repository revision: `{report['git_commit']}`",'']
    lines += ['| Scenario | Security | Functionality | Complete | Exit |',
              '|---|---|---|---|---:|']
    for r in report['scenarios']:
        lines.append(f"| {r['scenario']} | {r['security_status']} | {r['functionality_status']} | {r['analysis_complete']} | {r['exit_code']} |")
    lines += ['', f"**Overall CI result:** {report['status']} ({report['exit_code']})",'']
    for r in report['scenarios']:
        lines += [f"## {r['scenario']}",
                  f"- Correlation: {r['correlation']['strength']} — {r['correlation']['reason']}",
                  f"- Hardening changes: {', '.join(r['hardening']['warnings']) if r['hardening']['warnings'] else 'none observed'}",
                  f"- Reproduction bundles: {len(r['generated_regressions'])}"]
        for test in r['security_tests']:
            lines += [f"- Attack `{test['case_id']}`: base `{test['base_state']}`, patch `{test['patched_state']}`, patch reference `{test['patched_oracle_pass']}`"]
        for test in r['functional_tests']:
            lines += [f"- Function `{test['case_id']}`: baseline `{test['base_matches_reference']}`, patch `{test['patched_matches_reference']}`"]
        lines.append('')
    lines += ['Scope: observed dynamic behavior on declared inputs and build configurations only.',
              'A finding/diff overlap is evidence of correlation, not proof of causality or global absence of vulnerabilities.', '']
    return '\n'.join(lines)


def main(argv=None):
    p=argparse.ArgumentParser(description='Evidence-based C/C++ ELF patch validator')
    p.add_argument('--config',action='append',required=True,
                   help='Scenario JSON path; repeat for multiple targets/patches')
    p.add_argument('--out',default='artifacts/results')
    p.add_argument('--allow-local',action='store_true',
                   help='Run untrusted binaries outside isolation (ONLY in disposable VM/container)')
    p.add_argument('--skip-minimize',action='store_true')
    ns=p.parse_args(argv)
    if not ns.allow_local and os.environ.get('PATCHGUARD_ISOLATED')!='1':
        print('Refusing to execute untrusted C: use Docker runner or --allow-local in a disposable VM.',file=sys.stderr)
        return 30
    root=ROOT
    out=(root/ns.out).resolve()
    if not out.is_relative_to(root):
        print('Output directory must be inside checkout',file=sys.stderr)
        return 30
    out.mkdir(parents=True,exist_ok=True)
    compiler_info=command(['gcc','--version'],root)
    jsonc_info=command(['pkg-config','--modversion','json-c'],root) if __import__('shutil').which('pkg-config') else None
    report={'tool':'PatchGuard 1.0.0',
            'compiler':compiler_info['stdout'].splitlines()[0] if compiler_info['returncode']==0 else 'unknown',
            'json_c_version':jsonc_info['stdout'].strip() if jsonc_info and jsonc_info['returncode']==0 else 'unknown',
            'git_commit':git_revision(root),
            'platform':platform.platform(),'python':sys.version.split()[0],
            'scenarios':[]}
    for cfg_path in ns.config:
        try:
            path=(root/cfg_path).resolve()
            if not path.is_relative_to(root):
                raise ValueError('configuration outside repository')
            cfg=json.loads(path.read_text(encoding='utf-8'))
            report['scenarios'].append(evaluate(root,cfg,out,not ns.skip_minimize))
        except (Exception) as exc:
            report['scenarios'].append({'scenario':cfg_path,'status':'BUILD_OR_CONFIG_ERROR',
                'security_status':'unknown','functionality_status':'unknown',
                'analysis_complete':False,'exit_code':30,'error':str(exc),
                'traceback':traceback.format_exc()})
    present={r['exit_code'] for r in report['scenarios']}
    code=next((x for x in (40,20,10,30,0) if x in present),0)
    report['exit_code']=code
    report['status']=STATUS_TEXT[code]
    write_json(out/'report.json',report)
    (out/'report.md').write_text(markdown_report_safe(report),encoding='utf-8')
    print(f'PatchGuard: {report["status"]} ({code})')
    for r in report['scenarios']:
        print(f"  {r['scenario']}: {r['status']} ({r['exit_code']})")
        if 'error' in r:
            print('   Error:',r['error'])
    print('Reports:',out/'report.json',out/'report.md')
    return code


def markdown_report_safe(report):
    if all('correlation' in r for r in report['scenarios']):
        return markdown_report(report)
    return '# PatchGuard Build / Configuration Error\n\n' + '\n'.join(
            f"- {r['scenario']}: {r.get('error',r.get('status'))}" for r in report['scenarios']) + '\n'


if __name__ == '__main__':
    sys.exit(main())
