"""Reject accidental binaries, package outputs and obvious secrets in the Git index."""
from pathlib import PurePosixPath
import re
import subprocess
import sys

ALLOWED_SUFFIXES = {'.cs', '.csproj', '.config', '.cpp', '.h', '.def', '.ps1', '.py', '.md', '.yml'}
ALLOWED_NAMES = {'LICENSE', '.gitignore', '.gitattributes'}
FORBIDDEN_DIRS = {'bin', 'obj', 'build', 'vendor', 'toolchain', 'reports', '_pc_compat', '_local_security_audit'}
SECRET_PATTERNS = (
    re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(rb'github_pat_[A-Za-z0-9_]{30,}'),
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
)


def main():
    raw = subprocess.check_output(['git', 'ls-files', '-z'])
    names = [name.decode('utf-8') for name in raw.split(b'\0') if name]
    if not names:
        raise SystemExit('No tracked files to check. Stage the intended source files first.')
    failures = []
    total = 0
    for name in names:
        path = PurePosixPath(name)
        data = subprocess.check_output(['git', 'show', ':' + name])
        total += len(data)
        reasons = []
        if path.name not in ALLOWED_NAMES and path.suffix.lower() not in ALLOWED_SUFFIXES:
            reasons.append('unexpected file type')
        if FORBIDDEN_DIRS.intersection(path.parts) or '.local.' in path.name or path.name.startswith('.env'):
            reasons.append('local-only path')
        if len(data) > 256 * 1024 or b'\0' in data:
            reasons.append('binary or oversized content')
        if any(pattern.search(data) for pattern in SECRET_PATTERNS):
            reasons.append('possible credential')
        try:
            text = data.decode('utf-8-sig')
            if re.search('[\u0400-\u04ff]', text):
                reasons.append('non-English Cyrillic text')
        except UnicodeDecodeError:
            reasons.append('non-UTF-8 content')
        if reasons:
            failures.append(name + ': ' + ', '.join(reasons))
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'SOURCE_TREE_PASS: {len(names)} tracked text files, {total} bytes.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
