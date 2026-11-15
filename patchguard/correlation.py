"""Source diff analysis plus runtime evidence. Correlation is not causation."""
import re
from .runner import command

HUNK = re.compile(r'@@ -(?P<old>\d+)(?:,(?P<oldn>\d+))? \+(?P<new>\d+)(?:,(?P<newn>\d+))? @@')
FUN = re.compile(r'^\s*(?:static\s+)?(?:void|int|char\s*\*|size_t|long)\s+([A-Za-z_]\w*)\s*\(')


CJSON_FUN = re.compile(r'^\s*CJSON_PUBLIC\([^)]*\)\s+([A-Za-z_]\w*)\s*\(')

def function_at(lines, line):
    prior = None
    for i, value in enumerate(lines, start=1):
        if i > line:
            break
        m = FUN.search(value) or CJSON_FUN.search(value)
        if m:
            prior = m.group(1)
    return prior


def correlate(root, old_source, new_source, finding, before_result, after_result):
    # Git --no-index produces unified diff with accurate hunk line ranges.
    diff = command(['git', 'diff', '--no-index', '-U0', '--', old_source, new_source], root)
    if diff['returncode'] not in (0,1):
        return {'strength':'unknown', 'reason':'diff unavailable', 'diff':'', 'hunks':[]}
    text = diff['stdout']
    hunks = []
    old_lines = (root/old_source).read_text().splitlines()
    new_lines = (root/new_source).read_text().splitlines()
    for m in HUNK.finditer(text):
        o,n = int(m.group('old')), int(m.group('new'))
        hunks.append({'base_line':o, 'base_count':(int(m.group('oldn')) if m.group('oldn') is not None else 1),
                      'patched_line':n, 'patched_count':(int(m.group('newn')) if m.group('newn') is not None else 1),
                      'base_function':function_at(old_lines,o),
                      'patched_function':function_at(new_lines,n)})
    loc = finding.get('location') or ''
    frame_func = finding.get('function')
    location_line = re.search(r':(\d+)(?::\d+)?', loc)
    line = int(location_line.group(1)) if location_line else None
    same_line = bool(line and any(h['base_count'] > 0 and h['base_line'] <= line < h['base_line']+h['base_count'] for h in hunks))
    same_function = bool(frame_func and any(frame_func in (h['base_function'],h['patched_function']) for h in hunks))
    if same_line:
        strength,reason = 'direct_line_overlap','crash line overlaps changed source lines'
    elif same_function:
        strength,reason = 'function_overlap','runtime stack-frame function contains patch changes'
    else:
        strength,reason = 'unknown','no supported stack-frame/diff overlap; causality not established'
    return {'strength':strength,'reason':reason,'diff':text[:32000],
            'hunks':hunks,'base_crash':finding,'observed_before':before_result,
            'observed_after':after_result}
