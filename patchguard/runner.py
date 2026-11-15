"""Build and execute isolated test *processes*. OS isolation is provided by Docker outside this module."""
import hashlib
import os
import re
import signal
from pathlib import Path
import shlex
import subprocess
import tempfile
import time


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(args, cwd, timeout=30, data=None, env=None):
    start = time.monotonic()
    try:
        p = subprocess.run(args, cwd=cwd, input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, env=env)
        return {"argv": args, "returncode": p.returncode,
                "stdout": p.stdout.decode('utf-8', 'replace')[-16000:],
                "stderr": p.stderr.decode('utf-8', 'replace')[-32000:],
                "elapsed_ms": round((time.monotonic()-start)*1000),
                "timeout": False}
    except subprocess.TimeoutExpired as e:
        return {"argv": args, "returncode": None,
                "stdout": (e.stdout or b'').decode('utf-8','replace')[-16000:],
                "stderr": (e.stderr or b'').decode('utf-8','replace')[-32000:],
                "elapsed_ms": round((time.monotonic()-start)*1000),
                "timeout": True}


def build(root, source_rel, target, kind, output, version="base"):
    """No shell execution: the JSON config lists sources and compiler options."""
    src = (root / source_rel).resolve()
    if not src.is_file() or not src.is_relative_to(root.resolve()):
        raise ValueError(f"source outside repository/missing: {source_rel}")
    output.parent.mkdir(parents=True, exist_ok=True)
    args = ["gcc", "-std=c11", "-Wall", "-Wextra", "-Wno-unused-parameter", "-fno-omit-frame-pointer", "-g", "-O1"]
    if kind == 'sanitized':
        args += ["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    else:
        args += ["-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now"]
    args += [str(src), "-o", str(output)]
    for cflag in (target.get('extra_cflags', []) + target.get('extra_cflags_by_version', {}).get(version, [])):
        if not isinstance(cflag, str) or len(cflag)>200:
            raise ValueError("invalid compiler flag")
        args.append(cflag)
    for lib in target.get('libraries', []):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", lib):
            raise ValueError("invalid library name")
        args.append('-l' + lib)
    custom = target.get('build_commands',{}).get(f'{version}_{kind}',target.get('build_commands',{}).get(kind))
    if custom is not None:
        if not isinstance(custom,list) or not custom or any(not isinstance(v,str) for v in custom):
            raise ValueError('build_commands must be arrays of command tokens')
        args = [v.replace('{source}',str(src)).replace('{binary}',str(output))
                .replace('{root}',str(root)) for v in custom]
    result = command(args, cwd=root, timeout=60)
    result['source'] = str(src.relative_to(root))
    if result['returncode'] == 0:
        result['binary_sha256'] = sha256(output)
    return result


def run(binary, sample, mode='stdin', timeout=3, extra_env=None):
    """Input modes: stdin, argv, file. File/argv allow new targets via JSON only."""
    env = os.environ.copy()
    env.update({'ASAN_OPTIONS': 'detect_leaks=0:abort_on_error=1:print_stacktrace=1',
                'UBSAN_OPTIONS': 'print_stacktrace=1:halt_on_error=1'})
    if extra_env:
        env.update(extra_env)
    if mode == 'stdin':
        return command([str(binary)],cwd=binary.parent,timeout=timeout,data=sample,env=env)
    if mode == 'argv':
        arg=sample.decode('utf-8')
        if '\x00' in arg:
            raise ValueError('argv cannot include NUL bytes')
        return command([str(binary),arg],cwd=binary.parent,timeout=timeout,env=env)
    if mode == 'file':
        with tempfile.TemporaryDirectory() as tmp:
            name=Path(tmp)/'input.bin'
            name.write_bytes(sample)
            return command([str(binary),str(name)],cwd=binary.parent,timeout=timeout,env=env)
    raise ValueError(f'unknown input mode: {mode}')
