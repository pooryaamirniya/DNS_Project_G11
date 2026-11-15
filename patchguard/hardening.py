"""ELF hardening inspection: observations, not claims about runtime ASLR or comprehensive canaries."""
from .runner import command


def inspect(binary):
    segments = command(['readelf', '-Wl', str(binary)], binary.parent)
    header = command(['readelf', '-Wh', str(binary)], binary.parent)
    dyn = command(['readelf', '-Wd', str(binary)], binary.parent)
    syms = command(['readelf', '-Ws', str(binary)], binary.parent)
    if any(x['returncode'] != 0 for x in [segments, header, dyn, syms]):
        raise RuntimeError('readelf failed')
    stack_lines = [x.strip() for x in segments['stdout'].splitlines() if 'GNU_STACK' in x]
    relro_lines = [x.strip() for x in segments['stdout'].splitlines() if 'GNU_RELRO' in x]
    type_lines = [x.strip() for x in header['stdout'].splitlines() if x.strip().startswith('Type:')]
    bind_lines = [x.strip() for x in dyn['stdout'].splitlines() if 'BIND_NOW' in x or 'FLAGS' in x and 'NOW' in x]
    canary_lines = [x.strip() for x in syms['stdout'].splitlines() if '__stack_chk_fail' in x]
    nx = bool(stack_lines) and not any('RWE' in x or 'RWX' in x for x in stack_lines)
    pie = any('DYN' in x for x in type_lines)
    relro = 'Full' if relro_lines and bind_lines else 'Partial' if relro_lines else 'None'
    return {'NX': nx, 'PIE': pie, 'RELRO': relro, 'Canary_symbol': bool(canary_lines),
            'evidence': {'GNU_STACK': stack_lines, 'GNU_RELRO': relro_lines,
                         'ELF_Type': type_lines, 'BIND_NOW': bind_lines,
                         'Canary_symbol': canary_lines[:4]}}


def compare(before, after):
    drops = []
    for k in ('NX','PIE','Canary_symbol'):
        if before[k] and not after[k]:
            drops.append(f'{k} disabled in patched release')
    weights = {'None': 0, 'Partial': 1, 'Full': 2}
    if weights[after['RELRO']] < weights[before['RELRO']]:
        drops.append(f"RELRO weakened: {before['RELRO']} -> {after['RELRO']}")
    return drops
