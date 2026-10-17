"""Offline source/provenance guard; accepts Git's CRLF/LF conversion, not code drift."""
import hashlib
import json
import pathlib

base = pathlib.Path(__file__).resolve().parent
manifest = json.loads((base / 'provenance.json').read_text(encoding='utf-8-sig'))
observed = {p.relative_to(base).as_posix(): p for directory in ['upstream', 'MITLibs']
            for p in (base / directory).rglob('*') if p.is_file()}
expected = {entry['path']: entry for entry in manifest['originalInputs']}
assert observed.keys() == expected.keys(), 'upstream source/native file set changed'
changed = []
for name, file in observed.items():
    data = file.read_bytes()
    if expected[name]['normalizeLineEndings']:
        data = data.replace(b'\r\n', b'\n')
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected[name]['sha256']:
        changed.append(name)
        assert digest == manifest['patchedInputs'].get(name), ('unreviewed upstream modification', name)
assert set(changed) == set(manifest['patchedInputs']), ('patch missing or unexpected', changed)
assert hashlib.sha256((base / 'LICENSE').read_bytes().replace(b'\r\n', b'\n')).hexdigest() == manifest['licenseSha256'], 'upstream license changed'
print(f'Verified {len(expected)} upstream inputs: exactly the two reviewed TLS/cancellation files differ; native DLLs and license unchanged.')
