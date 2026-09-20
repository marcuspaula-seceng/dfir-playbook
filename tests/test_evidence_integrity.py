"""Focused regressions using synthetic files only; never run live collection."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PWSH = os.environ.get('PWSH') or shutil.which('pwsh')


def bash_executable():
    if os.environ.get('BASH_EXE'):
        return os.environ['BASH_EXE']
    if os.name == 'nt':
        # Windows' bash.exe can be a WSL launcher. Select Git Bash explicitly.
        git = shutil.which('git')
        if git:
            directory = Path(git).parent
            for candidate in (directory / 'bash.exe', directory.parent / 'bin/bash.exe'):
                if candidate.is_file():
                    return str(candidate)
        raise RuntimeError('Git Bash was not found; set BASH_EXE to its bash.exe')
    bash = shutil.which('bash')
    if not bash:
        raise RuntimeError('bash was not found')
    return bash


BASH = bash_executable()


def parse_manifest_line(line):
    # GNU checksum records use a space delimiter followed by text (space) or binary (*).
    match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *]([^\x00\r\n]+)', line)
    if not match:
        raise ValueError(f'Malformed SHA256 manifest record: {line!r}')
    return match.groups()


class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def bash_functions(self, source, body):
        # Load definitions only; the collector/acquisition entry point is removed.
        code = (ROOT / source).read_text(encoding='utf-8')
        self.assertTrue(code.rstrip().endswith('main "$@"'))
        fixture = self.work / 'functions.sh'
        fixture.write_text(code.rsplit('main "$@"', 1)[0], encoding='utf-8', newline='\n')
        script = 'source ' + shlex.quote(fixture.as_posix()) + '\n' + body
        return subprocess.run([BASH, '-c', script], cwd=self.work,
                              text=True, capture_output=True)

    def assert_manifest(self, manifest):
        names = []
        for line in manifest.read_text(encoding='utf-8-sig').splitlines():
            digest, name = parse_manifest_line(line)
            if os.name == 'nt' and name.startswith('/'):
                # Git Bash writes POSIX paths; Python on Windows needs native paths.
                name = subprocess.check_output(
                    [BASH, '-c', 'cygpath -w "$1"', 'cygpath', name], text=True).strip()
            file = Path(name)
            self.assertTrue(file.is_file(), f'Manifest target is not a file: {name!r}')
            self.assertNotEqual(file.resolve(), manifest.resolve())
            self.assertEqual(digest.lower(), hashlib.sha256(file.read_bytes()).hexdigest())
            names.append(file.name)
        self.assertTrue(names)
        return names

    def test_manifest_text_and_binary_markers(self):
        sample = self.work / 'synthetic sample.txt'
        sample.write_bytes(b'synthetic evidence\n')
        digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        manifest = self.work / 'SHA256SUMS.txt'
        for marker in (' ', '*'):
            with self.subTest(marker=marker):
                manifest.write_text(f'{digest} {marker}{sample}\n', encoding='utf-8')
                self.assertEqual(self.assert_manifest(manifest), [sample.name])

    def test_manifest_rejects_malformed_records(self):
        digest = 'a' * 64
        records = ('', 'not a checksum', f'{digest} filename', f'{digest} ?',
                   f'{digest} *', f'{"z" * 64}  file', f'{digest}  bad\x00name')
        for record in records:
            with self.subTest(record=record):
                with self.assertRaises(ValueError):
                    parse_manifest_line(record)

    def test_linux_final_metadata_and_repeated_manifest(self):
        (self.work / 'triage-metadata.txt').write_text('synthetic metadata\n')
        (self.work / 'sample.txt').write_text('synthetic evidence\n')
        # Invoke the actual finalisation/hash functions, not collection.
        result = self.bash_functions('scripts/bash/linux-triage.sh', '''
EVIDENCE_DIR="$PWD"
finish
hash_evidence
hash_evidence
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('triage-metadata.txt', self.assert_manifest(self.work / 'SHA256SUMS.txt'))

    def test_memory_hash_success(self):
        (self.work / 'memory.lime').write_text('synthetic memory bytes\n')
        result = self.bash_functions('scripts/bash/memory-capture.sh', '''
OUTPUT_DIR="$PWD"; OUTPUT_FILE="$PWD/memory.lime"; LOG_FILE="$PWD/capture.log"; METHOD=avml
hash_image
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_manifest(self.work / 'SHA256SUMS.txt')

    def test_missing_memory_image_is_failure(self):
        result = self.bash_functions('scripts/bash/memory-capture.sh', '''
OUTPUT_DIR="$PWD"; OUTPUT_FILE="$PWD/missing.lime"; LOG_FILE="$PWD/capture.log"; METHOD=avml
hash_image
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Hash recorded.', result.stdout)
        self.assertIn('Memory image missing or empty', result.stdout + result.stderr)

    def test_memory_hash_command_failure_is_reported(self):
        (self.work / 'memory.lime').write_text('synthetic memory bytes\n')
        result = self.bash_functions('scripts/bash/memory-capture.sh', '''
OUTPUT_DIR="$PWD"; OUTPUT_FILE="$PWD/memory.lime"; LOG_FILE="$PWD/capture.log"; METHOD=avml
sha256sum() { return 1; }
hash_image
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Hash recorded.', result.stdout)
        self.assertIn('Hashing failed; integrity has not been verified', result.stdout + result.stderr)

    def test_kcore_copy_failure_is_not_success(self):
        result = self.bash_functions('scripts/bash/memory-capture.sh', '''
OUTPUT_DIR="$PWD"; OUTPUT_FILE="$PWD/memory.lime"; LOG_FILE="$PWD/capture.log"
grep() { printf 'MemTotal: 4096 kB\\n'; }
dd() { return 1; }
capture_kcore
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('copy finished', result.stdout)
        self.assertIn('kcore capture failed', result.stdout + result.stderr)

    @unittest.skipUnless(PWSH, 'pwsh unavailable; Windows finalisation not executed')
    def test_windows_final_metadata_and_repeated_manifest(self):
        (self.work / 'triage.log').write_text('synthetic log\n')
        (self.work / 'triage-metadata.txt').write_text('synthetic metadata\n')
        (self.work / 'sample.txt').write_text('synthetic evidence\n')
        code = (ROOT / 'scripts/powershell/windows-triage.ps1').read_text(encoding='utf-8')
        marker = '# Finalise metadata before hashing'
        self.assertIn(marker, code)
        # Evaluate only the finalisation block; no collector commands are loaded.
        tail = code.split(marker, 1)[1]
        preamble = '''
$ErrorActionPreference = 'Stop'
$EvidenceDir = Join-Path $env:FIXTURE_DIR '.'
function Write-Log {
    param([string]$Msg)
    Add-Content -LiteralPath (Join-Path $EvidenceDir 'triage.log') -Value $Msg
}
'''
        fixture = self.work / 'finalise.ps1'
        fixture.write_text(preamble + tail, encoding='utf-8')
        for _ in range(2):
            result = subprocess.run([PWSH, '-NoProfile', '-File', str(fixture)],
                                    env={**os.environ, 'FIXTURE_DIR': str(self.work)},
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            names = self.assert_manifest(self.work / 'SHA256SUMS.txt')
            self.assertIn('triage.log', names)
            self.assertIn('triage-metadata.txt', names)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-pwsh', action='store_true')
    args, remaining = parser.parse_known_args()
    if args.require_pwsh and not PWSH:
        parser.error('pwsh is required for this validation run')
    unittest.main(argv=[__file__, *remaining])
