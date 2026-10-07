#!/usr/bin/env python3
"""Delete OpenShift users whose AD account no longer exists, with everything that points at them.

A user is deleted only when:
  - every identity it has comes from the LDAP identity provider (IDP_NAME),
  - it is not listed in EXCLUDE_USERS,
  - a subtree search for (&(objectClass=person)(sAMAccountName=<user>)) under
    LDAP_BASE_DN succeeds and returns no entries.
For each such user it removes, in order: group memberships, RoleBindings and
ClusterRoleBindings whose only subjects are stale users (bindings shared with
anyone else are reported and left alone), the console user-settings Role and
ConfigMap behind such a binding, every Identity whose user is that user, and the User.
Identities whose User no longer exists are deleted too when their account is also gone from AD.

Any LDAP or API error aborts the run before anything is deleted. If more than
MAX_DELETE users would be deleted, the run aborts (protects against a bad base DN
or an AD problem). DRY_RUN=true (the default) only reports.
"""
import json
import os
import socket
import subprocess
import sys

LDAP_HOST = os.environ.get('LDAP_HOST', 'nfii.com')
LDAP_PORT = int(os.environ.get('LDAP_PORT', '389'))
BASE_DN = os.environ.get('LDAP_BASE_DN', 'DC=nfii,DC=com')
BIND_DN = os.environ['LDAP_BIND_DN']
BIND_PW_FILE = os.environ.get('LDAP_BIND_PW_FILE', '/etc/ldap-secret/bindPassword')
PROVIDER = os.environ.get('IDP_NAME', 'NFII')
DRY_RUN = os.environ.get('DRY_RUN', 'true').strip().lower() != 'false'
MAX_DELETE = int(os.environ.get('MAX_DELETE', '5'))
EXCLUDE = {u.strip().lower() for u in os.environ.get('EXCLUDE_USERS', '').split(',') if u.strip()}
CONSOLE_NS = 'openshift-console-user-settings'


# --- Minimal LDAPv3 client (BER): simple bind + subtree search. The cli image has no ldap tools. ---
def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, value):
    return bytes([tag]) + enc_len(len(value)) + value


def integer(n):
    return tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), 'big'))


def enum(n):
    return tlv(0x0a, bytes([n]))


def octets(s):
    return tlv(0x04, s.encode())


def seq(*parts):
    return tlv(0x30, b''.join(parts))


def children(buf):
    out, i = [], 0
    while i < len(buf):
        tag, n = buf[i], buf[i + 1]
        i += 2
        if n & 0x80:
            k = n & 0x7f
            n = int.from_bytes(buf[i:i + k], 'big')
            i += k
        out.append((tag, buf[i:i + n]))
        i += n
    return out


class LDAP:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=15)
        self.sock.settimeout(30)
        self.msgid = 0

    def _read(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError('LDAP server closed the connection')
            data += chunk
        return data

    def _send(self, op):
        self.msgid += 1
        self.sock.sendall(seq(integer(self.msgid), op))

    def _recv(self):
        while True:
            hdr = self._read(2)
            n = hdr[1]
            if n & 0x80:
                n = int.from_bytes(self._read(n & 0x7f), 'big')
            msg = children(self._read(n))
            if int.from_bytes(msg[0][1], 'big') == self.msgid:
                return msg[1]

    @staticmethod
    def _result(val):
        f = children(val)
        return int.from_bytes(f[0][1], 'big'), f[2][1].decode(errors='replace')

    def bind(self, dn, password):
        self._send(tlv(0x60, integer(3) + octets(dn) + tlv(0x80, password.encode())))
        tag, val = self._recv()
        code, msg = self._result(val)
        if tag != 0x61 or code != 0:
            raise RuntimeError(f'LDAP bind failed (code {code}): {msg}')

    def account_exists(self, base, account):
        flt = tlv(0xa0, tlv(0xa3, octets('objectClass') + octets('person'))
                  + tlv(0xa3, octets('sAMAccountName') + octets(account)))
        # base, scope=subtree, derefAliases=never, sizeLimit=2, timeLimit=10s, typesOnly, filter, attrs=1.1 (none)
        self._send(tlv(0x63, octets(base) + enum(2) + enum(0) + integer(2) + integer(10)
                       + tlv(0x01, b'\xff') + flt + seq(octets('1.1'))))
        found = 0
        while True:
            tag, val = self._recv()
            if tag == 0x64:      # SearchResultEntry
                found += 1
            elif tag == 0x73:    # SearchResultReference (AD DNS/config partitions) - ignore
                continue
            elif tag == 0x65:    # SearchResultDone
                code, msg = self._result(val)
                if code not in (0, 4):   # 4 = sizeLimitExceeded, still means it exists
                    raise RuntimeError(f'LDAP search for {account} failed (code {code}): {msg}')
                return found > 0
            else:
                raise RuntimeError(f'unexpected LDAP response tag {tag:#x}')

    def close(self):
        try:
            self._send(tlv(0x42, b''))  # UnbindRequest
        finally:
            self.sock.close()


def oc(*args):
    r = subprocess.run(['oc', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if r.returncode:
        raise RuntimeError(f"oc {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def console_extras(ns, binding):
    """Role and ConfigMap the web console creates next to a user-settings RoleBinding."""
    if ns == CONSOLE_NS and binding.startswith('user-settings-') and binding.endswith('-rolebinding'):
        base = binding[:-len('-rolebinding')]
        return base + '-role', base
    return None


def main():
    users = json.loads(oc('get', 'users', '-o', 'json'))['items']
    groups = json.loads(oc('get', 'groups', '-o', 'json'))['items']
    identities = json.loads(oc('get', 'identities', '-o', 'json'))['items']
    bindings = (json.loads(oc('get', 'rolebindings', '-A', '-o', 'json'))['items']
                + json.loads(oc('get', 'clusterrolebindings', '-o', 'json'))['items'])
    existing = {u['metadata']['name'] for u in users}

    with open(BIND_PW_FILE) as f:
        password = f.read().strip()
    ldap = LDAP(LDAP_HOST, LDAP_PORT)
    ldap.bind(BIND_DN, password)

    stale, orphans, skipped = [], [], 0
    try:
        for u in users:
            name = u['metadata']['name']
            ids = u.get('identities') or []
            if name.lower() in EXCLUDE or not ids or any(not i.startswith(PROVIDER + ':') for i in ids):
                skipped += 1
                continue
            if not ldap.account_exists(BASE_DN, name):
                stale.append(name)
        for i in identities:
            owner = (i.get('user') or {}).get('name', '')
            if owner in existing or i.get('providerName') != PROVIDER:
                continue
            account = (i.get('extra') or {}).get('preferred_username') or owner
            if account and account.lower() not in EXCLUDE and not ldap.account_exists(BASE_DN, account):
                orphans.append(i['metadata']['name'])
    finally:
        ldap.close()

    gone = set(stale)
    plan = {}
    for u in users:
        name = u['metadata']['name']
        if name not in gone:
            continue
        # identities listed on the user plus any identity that points at it without being listed
        ids = set(u.get('identities') or [])
        ids |= {i['metadata']['name'] for i in identities if (i.get('user') or {}).get('name') == name}
        plan[name] = {'groups': [g['metadata']['name'] for g in groups if name in (g.get('users') or [])],
                      'identities': sorted(ids)}

    delete_bindings, shared = [], []
    for b in bindings:
        subjects = b.get('subjects') or []
        hit = [s['name'] for s in subjects if s.get('kind') == 'User' and s.get('name') in gone]
        if not hit:
            continue
        entry = (b['metadata'].get('namespace'), b['metadata']['name'], b['roleRef']['name'])
        if len(hit) == len(subjects):
            delete_bindings.append(entry)
        else:
            shared.append(entry + (hit,))

    mode = 'DRY RUN' if DRY_RUN else 'LIVE'
    print(f'[{mode}] checked {len(users) - skipped} {PROVIDER} users against LDAP ({skipped} skipped); '
          f'{len(stale)} no longer exist in LDAP')
    for name in stale:
        p = plan[name]
        print(f'  - user {name}  identities={len(p["identities"])}  groups={p["groups"] or "-"}')
    print(f'bindings to delete: {len(delete_bindings)}')
    for ns, binding, role in delete_bindings:
        extra = console_extras(ns, binding)
        where = f'rolebinding {ns}/{binding}' if ns else f'clusterrolebinding {binding}'
        print(f'  - {where} -> {role}' + (f'  (+ role {extra[0]}, configmap {extra[1]})' if extra else ''))
    for ns, binding, role, hit in shared:
        print(f'  ! shared binding left alone: {ns or "(cluster)"}/{binding} -> {role}, stale subjects {hit}')
    print(f'orphan identities (user already gone, account gone from AD): {len(orphans)}')
    for n in orphans:
        print(f'  - identity {n}')

    if len(stale) > MAX_DELETE:
        print(f'ABORT: {len(stale)} users exceeds MAX_DELETE={MAX_DELETE}; nothing deleted', file=sys.stderr)
        return 1
    if DRY_RUN:
        return 0

    failed = 0

    def run(desc, *args):
        nonlocal failed
        try:
            oc(*args)
            print(f'done: {desc}')
        except RuntimeError as e:
            failed += 1
            print(f'ERROR {desc}: {e}', file=sys.stderr)

    for name in stale:
        for g in plan[name]['groups']:
            run(f'removed {name} from group {g}', 'adm', 'groups', 'remove-users', g, name)
    for ns, binding, _ in delete_bindings:
        if ns:
            run(f'deleted rolebinding {ns}/{binding}', 'delete', 'rolebinding', binding, '-n', ns, '--ignore-not-found')
            extra = console_extras(ns, binding)
            if extra:
                run(f'deleted role {ns}/{extra[0]}', 'delete', 'role', extra[0], '-n', ns, '--ignore-not-found')
                run(f'deleted configmap {ns}/{extra[1]}', 'delete', 'configmap', extra[1], '-n', ns, '--ignore-not-found')
        else:
            run(f'deleted clusterrolebinding {binding}', 'delete', 'clusterrolebinding', binding, '--ignore-not-found')
    for name in stale:
        for i in plan[name]['identities']:
            run(f'deleted identity {i}', 'delete', 'identity', i, '--ignore-not-found')
        run(f'deleted user {name}', 'delete', 'user', name, '--ignore-not-found')
    for i in orphans:
        run(f'deleted orphan identity {i}', 'delete', 'identity', i, '--ignore-not-found')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
