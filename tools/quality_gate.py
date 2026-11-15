#!/usr/bin/env python3
"""Independent release-quality gate for PatchGuard evidence.

Does NOT generate labels or modify the PatchGuard classifier. It checks
on-disk artifacts of the real Docker runs, verifies source integrity, and
validates each case's evidence instead of trusting '9/9 passed' alone.

Runs safely outside Docker; it reads project files and writes its own report.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

EXPECTED = {
    'frame-correct': 0, 'frame-incomplete': 10, 'frame-regression': 20,
    'cjsonreal-correct': 0, 'cjsonreal-incomplete': 10, 'cjsonreal-regression': 20,
}
MODE_EXIT = {'pass': 0, 'incomplete': 10, 'regression': 20,
             'new_issue': 10, 'inconclusive': 40, 'build_error': 30}
MODE_SECURITY = {'pass': 'fixed', 'incomplete': 'incomplete',
                 'regression': 'fixed', 'new_issue': 'new_issue',
                 'inconclusive': 'inconclusive'}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Gate:
    def __init__(self, root: Path, strict: bool = False):
        self.root = root.resolve()
        self.strict = strict
        self.checks: list[dict] = []

    def add(self, key: str, ok: bool, explanation: str, warning: bool = False):
        self.checks.append({'id': key, 'ok': bool(ok),
                            'level': 'WARNING' if warning else 'ERROR',
                            'detail': explanation})

    def exists(self, rel: str) -> bool:
        return (self.root / rel).is_file()

    def load(self, rel: str) -> dict | None:
        path = self.root / rel
        if not path.is_file():
            self.add('present:'+rel, False, f'Missing required evidence: {rel}')
            return None
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError, OSError) as exc:
            self.add('parse:'+rel, False, f'Invalid JSON in {rel}: {exc}')
            return None

    def source(self, source: str, checksum: str, key: str):
        # Reject absolute paths and traversal; evidence must live in checkout.
        try:
            path = (self.root / source).resolve()
            inside = path.is_relative_to(self.root)
        except (TypeError, OSError, ValueError):
            inside = False
            path = self.root
        if not inside or not path.is_file():
            self.add(key, False, f'Source path not found inside checkout: {source}')
            return
        self.add(key, sha256(path.read_bytes()) == checksum,
                 f'Source hash from report must match current file: {source}')

    def upstream(self):
        path = 'targets/cjsonreal/source_manifest.json'
        manifest = self.load(path)
        if manifest is None:
            return
        self.add('upstream:cve', manifest.get('cve') == 'CVE-2024-31755',
                 'cJSON target must identify independently documented CVE')
        for key, tag in [('original_release','v1.7.17'),
                         ('patched_release','v1.7.18')]:
            info = manifest.get(key, {})
            self.add('upstream:'+key, info.get('tag') == tag,
                     f'Expected real upstream tag {tag}')
            refs = info.get('files_sha256', {})
            for filename in ('cJSON.c','cJSON.h','LICENSE'):
                recorded = refs.get(filename)
                rel = f'targets/cjsonreal/upstream/{tag}/{filename}'
                if not recorded:
                    self.add('upstream-hash:'+rel, False, 'No recorded SHA-256')
                else:
                    self.source(rel, recorded, 'upstream-hash:'+rel)
        self.add('upstream:oracle', self.exists('docs/oracle-cjsonreal.md'),
                 'Independent oracle description for real upstream target must exist')

    def official_matrix(self):
        report = self.load('artifacts/ci/report.json')
        if report is None:
            return
        scenarios = report.get('scenarios', [])
        if not isinstance(scenarios, list):
            self.add('matrix:shape', False, 'Expected report.scenarios array')
            return
        by_name = {r.get('scenario'):r for r in scenarios if isinstance(r,dict)}
        self.add('matrix:names', set(by_name) == set(EXPECTED) and len(scenarios) == 6,
                 f'Exactly six current targets expected; found {list(by_name)}')
        self.add('matrix:overall', report.get('exit_code') == 20,
                 'Aggregate six-variant run should report FUNC_REGRESSION=20')
        for name, code in EXPECTED.items():
            r = by_name.get(name)
            if r is None:
                continue
            prefix = 'matrix:' + name
            self.add(prefix+':exit', r.get('exit_code') == code,
                     f'Expected code {code}, actual {r.get("exit_code")}')
            self.add(prefix+':complete', r.get('analysis_complete') is True,
                     'Official matrix should have complete analysis')
            for variant in ('base','patch'):
                version = r.get('versions',{}).get(variant,{})
                if version.get('source_sha256') and version.get('source'):
                    self.source(version['source'],version['source_sha256'],
                                prefix+':source:'+variant)
                else:
                    self.add(prefix+':source:'+variant,False,
                             'Missing source path/hash evidence')
            builds = r.get('builds',{})
            self.add(prefix+':builds', all(
                builds.get(label,{}).get('returncode') == 0
                for label in ('base_release','base_sanitized',
                              'patch_release','patch_sanitized')),
                'All four release/sanitized builds must succeed')
            for b in ('base','patched'):
                hard = r.get('hardening',{}).get(b,{})
                self.add(prefix+':hardening:'+b,
                         all(x in hard for x in ('NX','PIE','RELRO','Canary_symbol')),
                         'Hardening measurements must contain four ELF properties')
            drops = r.get('hardening',{}).get('warnings',[])
            self.add(prefix+':hardening-drops', not drops,
                     f'Potential weakened binary protections: {drops}', warning=True)
            correlation = r.get('correlation',{})
            self.add(prefix+':correlation',
                     correlation.get('strength') in ('direct_line_overlap','function_overlap'),
                     'Patch-to-finding correlation should have runtime source evidence',
                     warning=True)
            attacks = r.get('security_tests',[])
            functional = r.get('functional_tests',[])
            self.add(prefix+':attack-count',len(attacks)>=2,
                     'At least 2 security attacks per scenario')
            self.add(prefix+':function-count',len(functional)>=4,
                     'At least 4 functional tests per scenario')
            base_confirmed = all(t.get('base_state')=='confirmed' for t in attacks)
            self.add(prefix+':base-confirmed',base_confirmed and bool(attacks),
                     'Every declared security testcase must reproduce on base')
            for idx,attack in enumerate(attacks):
                for side in ('base_sanitized','patched_sanitized'):
                    trials = attack.get(side,[])
                    self.add(f'{prefix}:3-runs:{idx}:{side}',
                             len(trials) == 3,
                             'Three recorded sanitizer replays per security case')
                if attack.get('reproducer'):
                    rep = attack['reproducer']
                    path = rep.get('path')
                    if path:
                        rel = 'artifacts/ci/'+path+'/manifest.json'
                        self.add(f'{prefix}:reproducer:{idx}',self.exists(rel),
                                 f'Reproducer bundle expected at {rel}')
            self.add(prefix+':reproducer-any',bool(r.get('generated_regressions')),
                     'Automatically minimized reproducer bundles should exist')
            semantics = name.split('-',1)[1]
            if semantics == 'correct':
                ok_security = all(t.get('patched_state')=='absent' and
                                  t.get('patched_oracle_pass') is True for t in attacks)
                ok_func = all(t.get('base_matches_reference') is True and
                              t.get('patched_matches_reference') is True for t in functional)
                self.add(prefix+':security',ok_security and r.get('security_status')=='fixed',
                         'All correct-patch security tests must be fixed and match independent oracle')
                self.add(prefix+':function',ok_func and r.get('functionality_status')=='pass',
                         'Correct patch must preserve every functional reference case')
            elif semantics == 'incomplete':
                remaining = any(t.get('patched_state')=='confirmed' for t in attacks)
                self.add(prefix+':incomplete',remaining and r.get('security_status')=='incomplete',
                         'Incomplete patch must retain *confirmed* original vulnerability')
            elif semantics == 'regression':
                broken = any(t.get('base_matches_reference') is True and
                             t.get('patched_matches_reference') is False for t in functional)
                self.add(prefix+':regression',broken and r.get('functionality_status')=='regression',
                         'Regression patch must break a valid baseline-passing reference')

    def blind_matrix(self):
        manifest = self.load('artifacts/blind-patches/manifest.json')
        summary = self.load('artifacts/blind-patches/summary.json')
        if manifest is None or summary is None:
            return
        cases = manifest.get('cases',[])
        results = summary.get('cases',[])
        ids = [c.get('candidate') for c in cases]
        self.add('blind:run-id',manifest.get('suite_id')==summary.get('suite_id'),
                 'Summary and suite manifest must describe same run')
        self.add('blind:unique',len(ids)==len(set(ids))==9,
                 'Nine uniquely named unknown candidates')
        modes = [c.get('mode') for c in cases]
        self.add('blind:modes',len(cases)==9 and
                 all(modes.count(k)==v for k,v in {'pass':2,'incomplete':2,
                       'regression':2,'new_issue':1,'inconclusive':1,'build_error':1}.items()),
                 'Nine distinct case roles and target coverage')
        self.add('blind:summary',summary.get('passed')==summary.get('total')==9,
                 'The independent nine-case harness expects 9/9 successful comparisons')
        by_result={c.get('candidate'):c for c in results}
        self.add('blind:summary-cases',set(ids)==set(by_result) and len(results)==9,
                 'Summary must match manifest candidate IDs exactly')
        for case in cases:
            cid = case.get('candidate','unknown')
            key = 'blind:'+cid
            mode = case.get('mode')
            result = by_result.get(cid,{})
            expected = MODE_EXIT.get(mode)
            self.add(key+':result',expected is not None and
                     case.get('expected')==expected and result.get('expected')==expected and
                     result.get('observed')==expected and result.get('passed') is True,
                     f'Expected {mode} to produce code {expected}')
            rel = f'artifacts/blind-patches/results/{cid}/report.json'
            report = self.load(rel)
            if report is None:
                continue
            entries = report.get('scenarios',[])
            if not entries:
                self.add(key+':report',False,'Scenario evidence missing')
                continue
            s = entries[0]
            self.add(key+':reported-exit',s.get('exit_code')==expected,
                     'Independent engine report must agree with harness expectation')
            if mode in MODE_SECURITY:
                self.add(key+':security',s.get('security_status')==MODE_SECURITY[mode],
                         f'Expected security_status={MODE_SECURITY[mode]}, observed {s.get("security_status")}')
            if mode == 'regression':
                self.add(key+':regression',s.get('functionality_status')=='regression',
                         'Observed behavioral regression must be independently recorded')
            if mode == 'pass':
                self.add(key+':complete',s.get('analysis_complete') is True and
                         s.get('functionality_status')=='pass',
                         'New correct patch needs complete analysis and preserved behavior')
            if mode == 'inconclusive':
                self.add(key+':inconclusive',s.get('analysis_complete') is False,
                         'Missing precondition must remain inconclusive')
            if mode == 'build_error':
                self.add(key+':build-error',bool(s.get('error')),
                         'Build error must be an actual recorded exception')

    def config_and_ci(self):
        for target in ('frame','cjsonreal'):
            for variant in ('correct','incomplete','regression'):
                rel=f'configs/{target}-{variant}.json'
                cfg=self.load(rel)
                if cfg:
                    self.add('config:'+target+'-'+variant,
                             bool(cfg.get('attacks')) and bool(cfg.get('functional')) and
                             self.exists(cfg.get('reference','')),
                             'Config must reference security cases, functional cases and an independent oracle')
        self.add('ci:existing',self.exists('.github/workflows/patchguard.yml'),
                 'Existing CI workflow must be present')
        self.add('ci:full',self.exists('.github/workflows/quality-gate.yml'),
                 'Quality-gate workflow must run official matrix and 9 blind tests')

    def save(self) -> int:
        errors=[x for x in self.checks if not x['ok'] and x['level']=='ERROR']
        warns=[x for x in self.checks if not x['ok'] and x['level']=='WARNING']
        code=1 if errors or (self.strict and warns) else 0
        report={'tool':'Independent PatchGuard Quality Gate',
                'checked_at_utc':datetime.now(timezone.utc).isoformat(),
                'project_root':str(self.root),
                'checks_total':len(self.checks),
                'errors':len(errors),'warnings':len(warns),
                'status':'PASS' if code==0 else 'FAIL',
                'strict_mode':self.strict,'checks':self.checks}
        folder=self.root/'artifacts'/'quality-gate'
        folder.mkdir(parents=True,exist_ok=True)
        (folder/'quality_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        lines=['# PatchGuard: Independent Release Quality Gate','',
               f"**Status:** {report['status']} | Errors: {len(errors)} | Warnings: {len(warns)}",
               f"Checked: {report['checked_at_utc']}",'',
               'This checker verifies evidence; it does not reproduce untrusted binaries itself.','']
        for label,items in [('Blocking findings', errors),('Warnings', warns)]:
            lines.append('## '+label)
            if not items:
                lines.append('None.')
            else:
                for entry in items:
                    lines.append(f"- `{entry['id']}`: {entry['detail']}")
            lines.append('')
        lines += ['## Summary',f"- Total checks: {len(self.checks)}",
                  f"- Passing checks: {sum(int(c['ok']) for c in self.checks)}",
                  '- Instructor approval and individual defense cannot be established by this checker.', '']
        (folder/'quality_report.md').write_text('\n'.join(lines),encoding='utf-8')
        print(f"Quality Gate: {report['status']} | {len(self.checks)} checks | {len(errors)} errors | {len(warns)} warnings")
        for x in errors+warns:
            print(f"  {x['level']}: {x['id']} — {x['detail']}")
        print('Reports:',folder/'quality_report.md',folder/'quality_report.json')
        return code


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description='Audit scoped PatchGuard evidence before final submission')
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--strict',action='store_true',
                        help='Also fail on evidence warnings such as unknown correlation')
    ns=parser.parse_args(argv)
    root=ns.root.resolve()
    if not (root/'patchguard'/'cli.py').is_file():
        parser.error('Expected the PatchGuard_Project1 root directory')
    gate=Gate(root,ns.strict)
    gate.upstream()
    gate.config_and_ci()
    gate.official_matrix()
    gate.blind_matrix()
    return gate.save()


if __name__=='__main__':
    sys.exit(main())
