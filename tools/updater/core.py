"""Signed, transactional release updater. The launcher holds Store.lock while playing."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
APP = 'ZDECHLAK'
PLATFORM = 'windows-x64'
CHANNEL = 'prototype'
ALLOWED_CHANNELS = frozenset({'prototype', 'test'})
LAUNCHER_NAMES = ('ZDECHLAK Launcher.exe', 'ZDECHLAK.exe')


class UpdateError(Exception):
    pass


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UpdateError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse_json(data):
    try:
        return json.loads(data, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise UpdateError('Invalid JSON') from exc


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_path(name):
    if not isinstance(name, str) or not 1 <= len(name) <= 220:
        raise UpdateError('Invalid path length/type')
    if not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
        raise UpdateError('Forbidden path characters: ' + name)
    parts = name.split('/')
    for part in parts:
        if not part or part in ('.', '..') or part.endswith('.') or len(part) > 100:
            raise UpdateError('Unsafe path: ' + name)
        stem = part.split('.')[0].upper()
        if stem in {'CON', 'PRN', 'AUX', 'NUL', 'CLOCK$'} or re.fullmatch(r'(COM|LPT)[0-9]', stem):
            raise UpdateError('Reserved Windows name: ' + name)
    if not (name in ('init.lua', 'otclientrc.lua', 'build-info.json', 'ZDECHLAK-client.exe', 'update-marker.txt') or
            (len(parts) == 1 and name.lower().endswith('.dll')) or
            (len(parts) > 1 and parts[0] in ('data', 'modules', 'mods', 'licenses', 'layouts'))):
        raise UpdateError('Path outside update allowlist: ' + name)
    return name


def assert_no_links(path):
    """Check parents too; Windows junctions/reparse points are forbidden."""
    path = Path(os.path.abspath(path))
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise UpdateError('Symlink/reparse point: ' + str(part))
    return path


def regular(path):
    assert_no_links(path)
    if not path.is_file():
        raise UpdateError('Expected regular file: ' + str(path))


def sync_dir(path):
    if os.name != 'nt':
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_json(path, value):
    assert_no_links(path)
    temp = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        with temp.open('xb') as handle:
            handle.write(json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def validate_endpoint(endpoint):
    try:
        parts = urlsplit(endpoint)
        port = parts.port
    except (TypeError, ValueError) as exc:
        raise UpdateError('Invalid endpoint') from exc
    if (parts.scheme != 'https' or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or not re.fullmatch(r'/[A-Za-z0-9_/-]*', parts.path)
            or any(p in ('.', '..') for p in parts.path.split('/'))):
        raise UpdateError('Endpoint requires HTTPS and a plain base path')
    if port is not None and not 1 <= port <= 65535:
        raise UpdateError('Invalid port')
    return endpoint.rstrip('/')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpdateError('HTTP redirects are forbidden')


class HttpsTransport:
    def __init__(self, context=None, timeout=15):
        self.context = context or ssl.create_default_context()
        if self.context.verify_mode != ssl.CERT_REQUIRED or not self.context.check_hostname:
            raise UpdateError('TLS certificate and hostname verification required')
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=self.context))

    def fetch(self, url, limit):
        if urlsplit(url).scheme != 'https':
            raise UpdateError('HTTPS required')
        try:
            with self.opener.open(url, timeout=self.timeout) as response:
                if response.status != 200 or response.geturl() != url:
                    raise UpdateError('Unexpected HTTP status or URL')
                length = response.headers.get('Content-Length')
                if length is not None and (not length.isdigit() or int(length) > limit):
                    raise UpdateError('Oversized/invalid Content-Length')
                data = response.read(limit + 1)
                if len(data) > limit or (length is not None and len(data) != int(length)):
                    raise UpdateError('Oversized/truncated response')
                return data
        except UpdateError:
            raise
        except Exception as exc:
            raise UpdateError('HTTPS download failed: ' + str(exc)) from exc


def _verify_envelope(envelope, public_key):
    if len(envelope) > MAX_MANIFEST:
        raise UpdateError('Manifest too large')
    outer = parse_json(envelope)
    try:
        if set(outer) != {'algorithm', 'payload', 'signature'} or outer['algorithm'] != 'Ed25519':
            raise UpdateError('Unsupported manifest envelope')
        payload = base64.b64decode(outer['payload'], validate=True)
        signature = base64.b64decode(outer['signature'], validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (ValueError, TypeError, KeyError, InvalidSignature) as exc:
        raise UpdateError('Invalid manifest signature') from exc
    return parse_json(payload), digest(payload), payload


def _validate_common_fields(doc, channel, *, require_kind=None):
    if type(doc.get('schema')) is not int or doc['schema'] != 1 or doc.get('app') != APP or doc.get('platform') != PLATFORM:
        raise UpdateError('Manifest target mismatch')
    if channel not in ALLOWED_CHANNELS or doc.get('channel') != channel:
        raise UpdateError('Manifest channel mismatch')
    for key in ('sequence', 'issued_at', 'expires_at'):
        if type(doc.get(key)) is not int or doc[key] < 1:
            raise UpdateError('Invalid manifest integer: ' + key)
    if not isinstance(doc.get('version'), str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?', doc['version']):
        raise UpdateError('Invalid version')
    if not 0 < doc['expires_at'] - doc['issued_at'] <= 31 * 86400:
        raise UpdateError('Invalid manifest validity interval')
    if require_kind is not None and doc.get('kind') != require_kind:
        raise UpdateError('Manifest kind mismatch')


def verify_manifest(envelope, public_key, *, check_time=True, now=None, channel=CHANNEL):
    doc, sha, _payload = _verify_envelope(envelope, public_key)
    required = {'schema', 'app', 'platform', 'channel', 'version', 'sequence', 'issued_at', 'expires_at', 'files'}
    if not isinstance(doc, dict) or set(doc) != required:
        raise UpdateError('Invalid manifest schema')
    _validate_common_fields(doc, channel)
    now = int(time.time()) if now is None else now
    if check_time and (doc['issued_at'] > now + 300 or doc['expires_at'] <= now):
        raise UpdateError('Expired or future manifest')
    if not isinstance(doc['files'], list) or not 1 <= len(doc['files']) <= 5000:
        raise UpdateError('Invalid file count')
    names = set()
    total = 0
    for entry in doc['files']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'size', 'sha256'}:
            raise UpdateError('Invalid file entry')
        name = validate_path(entry['path']).casefold()
        if name in names:
            raise UpdateError('Duplicate/case-colliding path')
        names.add(name)
        if type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_FILE:
            raise UpdateError('Invalid file size')
        if not isinstance(entry['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256']):
            raise UpdateError('Invalid SHA-256')
        total += entry['size']
    for name in names:
        parts = name.split('/')
        if any('/'.join(parts[:i]) in names for i in range(1, len(parts))):
            raise UpdateError('File/directory collision')
    if total > MAX_TOTAL:
        raise UpdateError('Release too large')
    return doc, sha


def verify_launcher_manifest(envelope, public_key, *, check_time=True, now=None, channel=CHANNEL):
    doc, sha, _payload = _verify_envelope(envelope, public_key)
    required = {'schema', 'app', 'platform', 'channel', 'kind', 'version', 'sequence', 'issued_at', 'expires_at', 'file'}
    if not isinstance(doc, dict) or set(doc) != required:
        raise UpdateError('Invalid launcher manifest schema')
    _validate_common_fields(doc, channel, require_kind='launcher')
    now = int(time.time()) if now is None else now
    if check_time and (doc['issued_at'] > now + 300 or doc['expires_at'] <= now):
        raise UpdateError('Expired or future launcher manifest')
    entry = doc['file']
    if not isinstance(entry, dict) or set(entry) != {'name', 'size', 'sha256'}:
        raise UpdateError('Invalid launcher file entry')
    if entry['name'] != 'ZDECHLAK-Launcher.exe':
        raise UpdateError('Invalid launcher payload name')
    if type(entry['size']) is not int or not 1 <= entry['size'] <= MAX_FILE:
        raise UpdateError('Invalid launcher size')
    if not isinstance(entry['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256']):
        raise UpdateError('Invalid launcher SHA-256')
    return doc, sha


class Store:
    def __init__(self, root, public_key, transport=None, progress=None, channel=CHANNEL):
        if channel not in ALLOWED_CHANNELS:
            raise UpdateError('Unsupported update channel')
        self.root = assert_no_links(Path(root))
        self.root.mkdir(parents=True, exist_ok=True)
        self.releases = self.root / 'releases'
        assert_no_links(self.releases)
        self.releases.mkdir(exist_ok=True)
        self.key = public_key
        self.channel = channel
        self.transport = transport or HttpsTransport()
        self.progress = progress or (lambda message: None)
        self.state_file = self.root / 'current.json'
        self.journal = self.root / 'transaction.json'

    @contextlib.contextmanager
    def lock(self):
        path = self.root / 'launcher.lock'
        assert_no_links(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if os.name == 'nt':
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b'0')
                os.lseek(fd, 0, 0)
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise UpdateError('ZDECHLAK is already running') from exc
            else:
                import fcntl
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise UpdateError('ZDECHLAK is already running') from exc
            yield
        finally:
            os.close(fd)

    def read_state(self):
        if not self.state_file.exists():
            assert_no_links(self.state_file)
            return None
        regular(self.state_file)
        value = parse_json(self.state_file.read_bytes())
        self.validate_state(value)
        return value

    @staticmethod
    def validate_state(value):
        if not isinstance(value, dict) or set(value) != {'active', 'previous', 'highest_sequence', 'manifest_digest'}:
            raise UpdateError('Invalid updater state')
        for key in ('active', 'previous'):
            if key == 'previous' and value[key] is None:
                continue
            if not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{32}', value[key]):
                raise UpdateError('Invalid release ID')
        if type(value['highest_sequence']) is not int or value['highest_sequence'] < 1:
            raise UpdateError('Invalid sequence state')
        if not isinstance(value['manifest_digest'], str) or not re.fullmatch('[a-f0-9]{64}', value['manifest_digest']):
            raise UpdateError('Invalid manifest digest state')

    def recover(self):
        assert_no_links(self.journal)
        if not self.journal.exists():
            return False
        regular(self.journal)
        record = parse_json(self.journal.read_bytes())
        if not isinstance(record, dict) or set(record) != {'old'}:
            raise UpdateError('Invalid recovery journal')
        old = record['old']
        if old is None:
            assert_no_links(self.state_file)
            self.state_file.unlink(missing_ok=True)
            sync_dir(self.root)
        else:
            self.validate_state(old)
            atomic_json(self.state_file, old)
        self.journal.unlink()
        sync_dir(self.root)
        self.progress('Przywrocono poprzednia wersje po przerwanej aktualizacji.')
        return True

    def release_manifest(self, release_id):
        if not re.fullmatch('[a-f0-9]{32}', release_id):
            raise UpdateError('Invalid release ID')
        path = self.releases / release_id / 'manifest.json'
        regular(path)
        data = path.read_bytes()
        doc, sha = verify_manifest(data, self.key, check_time=False, channel=self.channel)
        return path.parent, doc, sha

    def verify_release(self, release_id):
        path, doc, sha = self.release_manifest(release_id)
        for entry in doc['files']:
            dest = path / entry['path']
            regular(dest)
            if dest.stat().st_size != entry['size'] or digest(dest.read_bytes()) != entry['sha256']:
                raise UpdateError('Local file verification failed: ' + entry['path'])
        # Do not allow injected Lua modules/DLLs or stale deleted files in a release.
        allowed = {x['path'] for x in doc['files']} | {'manifest.json'}
        for child in path.rglob('*'):
            assert_no_links(child)
            if child.is_file() and child.relative_to(path).as_posix() not in allowed:
                raise UpdateError('Unmanaged file inside release: ' + str(child))
        return path, doc, sha

    def current(self):
        state = self.read_state()
        if state is None:
            raise UpdateError('No installed release')
        path, doc, sha = self.verify_release(state['active'])
        if sha != state['manifest_digest'] or doc['sequence'] > state['highest_sequence']:
            raise UpdateError('Local manifest/state mismatch')
        return path

    def install(self, envelope, endpoint, hook=None):
        endpoint = validate_endpoint(endpoint)
        doc, sha = verify_manifest(envelope, self.key, channel=self.channel)
        old = self.read_state()
        highest = old['highest_sequence'] if old else 0
        if old and sha == old['manifest_digest']:
            self.current()  # Even no-op updates verify every installed file.
            return {'updated': False, 'downloaded': [], 'version': doc['version']}
        if doc['sequence'] <= highest:
            raise UpdateError('Manifest rollback/replay rejected')
        previous_path = self.releases / old['active'] if old else None
        release_id = uuid.uuid4().hex
        stage = self.releases / release_id
        stage.mkdir()
        changed = []
        activated = False
        try:
            for entry in doc['files']:
                name = entry['path']
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                previous = previous_path / name if previous_path else None
                reusable = False
                if previous is not None:
                    assert_no_links(previous)
                    reusable = (previous.is_file() and previous.stat().st_size == entry['size']
                                and digest(previous.read_bytes()) == entry['sha256'])
                if reusable:
                    shutil.copyfile(previous, target)
                else:
                    self.progress('Pobieranie: ' + name)
                    data = self.transport.fetch(endpoint + '/objects/' + entry['sha256'], entry['size'])
                    if len(data) != entry['size'] or digest(data) != entry['sha256']:
                        raise UpdateError('SHA-256/size mismatch: ' + name)
                    with target.open('xb') as handle:
                        handle.write(data)
                    changed.append(name)
                # Windows FlushFileBuffers/_commit needs a writable handle.
                with target.open('r+b') as handle:
                    os.fsync(handle.fileno())
            atomic_json(stage / 'manifest.json', parse_json(envelope))
            for directory in sorted((p for p in stage.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                sync_dir(directory)
            sync_dir(stage)
            sync_dir(self.releases)
            self.verify_release(release_id)
            if hook:
                hook('before_activate')
            new = {'active': release_id, 'previous': old['active'] if old else None,
                   'highest_sequence': doc['sequence'], 'manifest_digest': sha}
            atomic_json(self.journal, {'old': old})
            atomic_json(self.state_file, new)
            activated = True
            if hook:
                hook('after_activate')
            self.current()
            self.journal.unlink()
            sync_dir(self.root)
            return {'updated': True, 'downloaded': changed, 'version': doc['version']}
        except Exception:
            if self.journal.exists():
                self.recover()
            elif activated:
                # A durability failure after journal removal leaves a complete signed release.
                # Keep it rather than deleting the directory referenced by current.json.
                raise
            shutil.rmtree(stage)
            raise

    def update(self, endpoint):
        endpoint = validate_endpoint(endpoint)
        self.recover()
        envelope = self.transport.fetch(endpoint + '/manifest.json', MAX_MANIFEST)
        return self.install(envelope, endpoint)

    def rollback(self):
        state = self.read_state()
        if not state or not state['previous']:
            raise UpdateError('No previous release available')
        _, _, sha = self.verify_release(state['previous'])
        old = dict(state)
        state['active'], state['previous'] = state['previous'], None
        state['manifest_digest'] = sha
        atomic_json(self.journal, {'old': old})
        atomic_json(self.state_file, state)
        self.current()
        self.journal.unlink()
        sync_dir(self.root)


class LauncherUpdater:
    """Download and apply a new launcher EXE via a helper process path.

    The running image is never overwritten in-place. A helper copy under
    runtime/helpers/ performs the replacement after the main process exits.
    """

    def __init__(self, runtime_root, bundle_root, public_key, transport=None, progress=None, channel=CHANNEL):
        if channel not in ALLOWED_CHANNELS:
            raise UpdateError('Unsupported update channel')
        self.runtime = assert_no_links(Path(runtime_root))
        self.bundle = assert_no_links(Path(bundle_root))
        self.key = public_key
        self.channel = channel
        self.transport = transport or HttpsTransport()
        self.progress = progress or (lambda message: None)
        self.state_file = self.runtime / 'launcher-state.json'
        self.pending_dir = self.runtime / 'launcher-pending'
        self.helpers_dir = self.runtime / 'helpers'
        self.backup_dir = self.runtime / 'launcher-backup'
        self.apply_journal = self.runtime / 'launcher-apply.json'
        self.pending_payload = self.pending_dir / 'ZDECHLAK-Launcher.exe'
        self.helper_exe = self.helpers_dir / 'zdechlak-apply.exe'

    def read_state(self):
        if not self.state_file.exists():
            assert_no_links(self.state_file)
            return None
        regular(self.state_file)
        value = parse_json(self.state_file.read_bytes())
        if not isinstance(value, dict) or set(value) != {'highest_sequence', 'version', 'manifest_digest', 'sha256'}:
            raise UpdateError('Invalid launcher state')
        if type(value['highest_sequence']) is not int or value['highest_sequence'] < 1:
            raise UpdateError('Invalid launcher sequence state')
        for key in ('version', 'manifest_digest', 'sha256'):
            if not isinstance(value[key], str):
                raise UpdateError('Invalid launcher state field: ' + key)
        return value

    def recover(self):
        """Finish or roll back an interrupted launcher apply."""
        assert_no_links(self.apply_journal)
        if not self.apply_journal.exists():
            return False
        regular(self.apply_journal)
        journal = parse_json(self.apply_journal.read_bytes())
        if not isinstance(journal, dict) or set(journal) != {
            'expected_sha256', 'sequence', 'version', 'manifest_digest', 'backup'
        }:
            raise UpdateError('Invalid launcher apply journal')
        payload = self.pending_payload
        if payload.is_file() and digest(payload.read_bytes()) == journal['expected_sha256']:
            self.progress('Dokonczanie aktualizacji launchera...')
            self._apply_from_pending(journal)
            return True
        if journal.get('backup') and self.backup_dir.is_dir():
            self.progress('Przywracanie launchera po nieudanej aktualizacji...')
            for name in LAUNCHER_NAMES:
                src = self.backup_dir / name
                if src.is_file():
                    dest = self.bundle / name
                    assert_no_links(dest)
                    shutil.copyfile(src, dest)
            self.apply_journal.unlink(missing_ok=True)
            sync_dir(self.runtime)
            return True
        self.apply_journal.unlink(missing_ok=True)
        return False

    def _apply_from_pending(self, journal):
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        for name in LAUNCHER_NAMES:
            current = self.bundle / name
            if current.is_file():
                shutil.copyfile(current, self.backup_dir / name)
        data = self.pending_payload.read_bytes()
        if digest(data) != journal['expected_sha256']:
            raise UpdateError('Launcher pending payload hash mismatch')
        for name in LAUNCHER_NAMES:
            target = self.bundle / name
            temp = self.bundle / ('.' + name.replace(' ', '_') + '.new')
            assert_no_links(target)
            with temp.open('wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, target)
        atomic_json(self.state_file, {
            'highest_sequence': journal['sequence'],
            'version': journal['version'],
            'manifest_digest': journal['manifest_digest'],
            'sha256': journal['expected_sha256'],
        })
        self.apply_journal.unlink(missing_ok=True)
        if self.pending_dir.exists():
            shutil.rmtree(self.pending_dir)
        sync_dir(self.runtime)
        sync_dir(self.bundle)

    def prepare(self, envelope, endpoint):
        """Download a newer launcher into pending and write apply journal. Returns True if apply needed."""
        endpoint = validate_endpoint(endpoint)
        doc, sha = verify_launcher_manifest(envelope, self.key, channel=self.channel)
        old = self.read_state()
        highest = old['highest_sequence'] if old else 0
        if old and sha == old['manifest_digest']:
            return False
        if doc['sequence'] <= highest:
            raise UpdateError('Launcher manifest rollback/replay rejected')
        entry = doc['file']
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.helpers_dir.mkdir(parents=True, exist_ok=True)
        self.progress('Pobieranie nowego launchera...')
        data = self.transport.fetch(endpoint + '/objects/' + entry['sha256'], entry['size'])
        if len(data) != entry['size'] or digest(data) != entry['sha256']:
            raise UpdateError('Launcher SHA-256/size mismatch')
        temp = self.pending_dir / ('.payload-' + uuid.uuid4().hex)
        try:
            with temp.open('xb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.pending_payload)
        finally:
            temp.unlink(missing_ok=True)
        # Helper must be a different path than the running image.
        shutil.copyfile(self.pending_payload, self.helper_exe)
        journal = {
            'expected_sha256': entry['sha256'],
            'sequence': doc['sequence'],
            'version': doc['version'],
            'manifest_digest': sha,
            'backup': True,
        }
        atomic_json(self.apply_journal, journal)
        return True

    def apply_now(self):
        if not self.apply_journal.exists():
            raise UpdateError('No launcher apply journal')
        journal = parse_json(self.apply_journal.read_bytes())
        self._apply_from_pending(journal)

    def update(self, endpoint):
        endpoint = validate_endpoint(endpoint)
        self.recover()
        try:
            envelope = self.transport.fetch(endpoint + '/launcher-manifest.json', MAX_MANIFEST)
        except UpdateError as exc:
            # Optional on channels that have not published a launcher yet.
            if '404' in str(exc) or 'Unexpected HTTP status' in str(exc):
                return False
            raise
        return self.prepare(envelope, endpoint)
