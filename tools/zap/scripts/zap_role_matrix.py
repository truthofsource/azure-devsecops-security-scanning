"""Prepare/run a fixed nonproduction passive matrix after fresh approved sign-ins.

Only ten GETs, no spider, active scan, business record retrieval or write route.
The invalid-query route exercises Admin/Caregiver authorization before a store
is opened. Raw responses and tokens stay in memory/the removed private container.
"""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request

from zap_authenticated import API, HOST, ROOT, alert_counts, image_pin

SETTINGS = '/api/workflownotifications/settings?view=zap-readonly-validation'
PHOTO = '/api/employees/zap-invalid-person/profile-photo'
ALLOWED = frozenset(('/api/health', '/api/me', SETTINGS, PHOTO))
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
TOKEN = re.compile(r'[A-Za-z0-9_.-]{50,16000}')


def private_token(path):
    if (not path.is_absolute() or path.is_symlink() or path.resolve().is_relative_to(ROOT)
            or not path.is_file() or path.stat().st_size > 16384):
        raise ValueError('Use a small private token file outside the repository')
    value = path.read_text(encoding='utf-8-sig').strip()
    if not TOKEN.fullmatch(value):
        raise ValueError('Invalid private token')
    return value


def request_text(path, token=None):
    if path not in ALLOWED or token is not None and not TOKEN.fullmatch(token):
        raise ValueError('Only the fixed read-only request catalog is permitted')
    auth = 'Authorization: Bearer ' + token + '\r\n' if token else ''
    return 'GET ' + API + path + ' HTTP/1.1\r\nHost: ' + HOST + '\r\n' + auth + 'Connection: close\r\n\r\n'


def evaluate(probe, admin, caregiver, admin_oid, caregiver_oid):
    if not UUID.fullmatch(admin_oid) or not UUID.fullmatch(caregiver_oid) or admin_oid == caregiver_oid or admin == caregiver:
        raise ValueError('Two distinct approved identities are required')
    results = []

    def check(path, token, actor, expected):
        status, body = probe(path, token)
        if status != expected:
            raise RuntimeError('Read-only matrix mismatch: ' + actor + ' ' + path.split('?')[0]
                               + ' expected ' + str(expected) + ', received ' + str(status)
                               + '; no clean result claimed')
        results.append({'route': path.split('?')[0], 'actor': actor, 'status': status})
        return body

    check('/api/health', None, 'anonymous', 200)
    check('/api/me', None, 'anonymous', 401)
    for label, token, oid, required in [('Admin', admin, admin_oid, 'Workforce.Admin'), ('Caregiver', caregiver, caregiver_oid, 'Workforce.Caregiver')]:
        data = json.loads(check('/api/me', token, label, 200))
        roles = data.get('roles', [])
        if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
            raise RuntimeError('Verified role array was not returned')
        if str(data.get('objectId', '')).lower() != oid or required not in roles:
            raise RuntimeError('Exact approved identity/role was not verified')
        if label == 'Caregiver' and set(roles) - {'Workforce.Caregiver'}:
            raise RuntimeError('Caregiver-only account required; Admin/other roles cannot prove denial')
    for route, admin_status in [(SETTINGS, 400), (PHOTO, 503)]:
        check(route, None, 'anonymous', 401)
        check(route, admin, 'Admin', admin_status)
        check(route, caregiver, 'Caregiver', 403)
    return results


@contextmanager
def passive_session(docker):
    name, key = 'workforce-zap-matrix-' + secrets.token_hex(6), secrets.token_hex(24)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def command(*args, timeout=120):
        p = subprocess.run([docker, *args], capture_output=True, timeout=timeout)
        if p.returncode:
            raise RuntimeError('Private ZAP container operation failed')
        return p.stdout.decode().strip()

    try:
        command('run', '--detach', '--name', name, '--platform', 'linux/amd64',
                '--publish', '127.0.0.1::8080', '--memory', '2g', '--cpus', '2',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', image_pin(),
                'zap.sh', '-daemon', '-host', '0.0.0.0', '-port', '8080',
                '-config', 'api.key=' + key, '-config', 'api.addrs.addr.name=.*',
                '-config', 'api.addrs.addr.regex=true', timeout=600)
        mapping = command('port', name, '8080/tcp')
        if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', mapping):
            raise RuntimeError('Private loopback-only binding required')

        def call(path, timeout=30, **values):
            data = urllib.parse.urlencode({'apikey': key, **values}).encode()
            req = urllib.request.Request('http://' + mapping + '/JSON/' + path + '/', data=data, headers={'Host': 'zap'})
            with opener.open(req, timeout=timeout) as response:
                return json.load(response)

        deadline = time.monotonic() + 360
        while True:
            try:
                call('core/view/version', timeout=2)
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise RuntimeError('ZAP startup timed out') from None
                time.sleep(1)
        sent = 0

        def probe(path, token):
            nonlocal sent
            raw = request_text(path, token)
            if sent >= 10:
                raise RuntimeError('Fixed request budget exhausted')
            sent += 1
            row = call('core/action/sendRequest', request=raw, followRedirects='false')['sendRequest'][0]
            return int(row['responseHeader'].split(' ', 2)[1]), row.get('responseBody', '')

        def finish():
            for attempt in range(60):
                if call('pscan/view/recordsToScan').get('recordsToScan') == '0':
                    break
                if attempt == 59:
                    raise RuntimeError('Passive analysis incomplete')
                time.sleep(1)
            rows = call('core/view/alerts', baseurl=API, start='0', count='1000')['alerts']
            if len(rows) >= 1000:
                raise RuntimeError('Alert budget exceeded')
            return alert_counts(rows)

        yield probe, finish
    finally:
        cleanup = subprocess.run([docker, 'rm', '--force', name], capture_output=True, timeout=30)
        if cleanup.returncode:
            raise RuntimeError('Private ZAP container cleanup must be verified')


def run(admin_file, caregiver_file, admin_oid, caregiver_oid, output, docker):
    if output.exists():
        raise ValueError('Choose a new safe summary path')
    admin, caregiver = private_token(admin_file), private_token(caregiver_file)
    if not UUID.fullmatch(admin_oid) or not UUID.fullmatch(caregiver_oid) or admin_oid == caregiver_oid or admin == caregiver:
        raise ValueError('Two distinct approved identities required before starting ZAP')
    with passive_session(docker) as (probe, finish):
        checks = evaluate(probe, admin, caregiver, admin_oid, caregiver_oid)
        alerts = finish()
    receipt = {'mode': 'fixed-role-matrix-passive', 'completed': True, 'requests': len(checks),
               'image': image_pin(), 'checks': checks, 'alerts': alerts, 'activeScan': False,
               'businessWrites': 0, 'businessRecordsRead': 0, 'identitiesVerified': True,
               'caregiverOnlyVerified': True, 'rawBodiesRetained': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return receipt


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('admin-token-file', 'caregiver-token-file'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('admin-object-id', 'caregiver-object-id'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--docker', default='docker')
    args = p.parse_args()
    try:
        print(json.dumps(run(args.admin_token_file, args.caregiver_token_file,
                             args.admin_object_id, args.caregiver_object_id, args.output, args.docker)))
    except Exception:
        raise SystemExit('Role-matrix check incomplete. Keep the API paused until fresh verified sign-ins and an owned test window are ready. No clean result claimed; private details withheld.') from None
