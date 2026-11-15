"""Conservative ASan/UBSan classification, intentionally avoiding blanket nonzero=>vulnerable."""
import re
import signal

ASAN = re.compile(r'ERROR: AddressSanitizer: ([\w-]+)')
UBSAN = re.compile(r'runtime error: (.*?)(?:\n|$)')
STACK_FRAME = re.compile(r'#\d+\s+0x[0-9a-f]+\s+in\s+([\w:~<>]+)\s+([^\n]+)')


def detect(result):
    stderr = result['stderr']
    observed = {'mechanism': 'none', 'error_type': None, 'function': None,
                'location': None, 'confirmed': False,
                'termination': {
                    'exit_code': result['returncode'],
                    'signal': (-result['returncode'] if result['returncode'] is not None and result['returncode'] < 0 else None),
                    'signal_name': (signal.Signals(-result['returncode']).name if result['returncode'] is not None and result['returncode'] < 0 and -result['returncode'] in signal.Signals._value2member_map_ else None),
                    'timeout': result['timeout']}}
    m = ASAN.search(stderr)
    if m:
        observed.update(mechanism='ASan', error_type=m.group(1), confirmed=True)
    else:
        m = UBSAN.search(stderr)
        if m:
            msg = m.group(1)
            kind = ('undefined-behavior: ' + msg.split(' at ')[0])[:140]
            observed.update(mechanism='UBSan', error_type=kind, confirmed=True)
    frames = list(STACK_FRAME.finditer(stderr))
    # Prefer the target's application frame over the ASan memcpy interceptor.
    frame = next(
        (
            f for f in frames
            if re.search(r'\.(?:c|cc|cpp|cxx|C):\d+\b', f.group(2))
            and not any(
                excluded in f.group(2).lower()
                for excluded in (
                    'sanitizer_common/',
                    'libsanitizer/',
                    'compiler-rt/',
                    '/glibc/',
                )
            )
        ),
        None
    )
    if frame:
        observed['function'] = frame.group(1)
        observed['location'] = frame.group(2).strip()
    if not observed['confirmed']:
        if result['timeout']:
            observed['mechanism'] = 'timeout'
        elif 'AddressSanitizer:DEADLYSIGNAL' in stderr:
            observed['mechanism'] = 'unclassified-sanitizer-signal'
        elif result['returncode'] is not None and result['returncode'] < 0:
            observed['mechanism'] = 'OS signal (unclassified)'
    return observed


def signature(finding):
    if not finding['confirmed']:
        return None
    # Function name provides location preservation without relying on line shifts.
    return (finding['error_type'], finding['function'])


def expected_behavior(result, oracle):
    return (not result['timeout'] and result['returncode'] == oracle['exit_code']
            and result['stdout'] == oracle['stdout'])
