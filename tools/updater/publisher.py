"""Offline signing utility. Never include the signing key in a player package."""
import argparse
import base64
import os
from pathlib import Path
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from updater.core import (
    APP, PLATFORM, CHANNEL, ALLOWED_CHANNELS, digest, json_bytes, validate_path,
    verify_manifest, verify_launcher_manifest, assert_no_links,
)


def generate_key(private_path, public_path):
    key = Ed25519PrivateKey.generate()
    private_path = Path(private_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    Path(public_path).write_text(base64.b64encode(public).decode('ascii') + '\n')
    return key


def sign_document(doc, key):
    payload = json_bytes(doc)
    return json_bytes({'algorithm': 'Ed25519', 'payload': base64.b64encode(payload).decode('ascii'),
                       'signature': base64.b64encode(key.sign(payload)).decode('ascii')})


def _write_objects(output, blobs, envelope, manifest_name='manifest.json'):
    objects = output / 'objects'
    objects.mkdir(parents=True, exist_ok=True)
    for sha, content in blobs.items():
        dest = objects / sha
        if dest.exists():
            if digest(dest.read_bytes()) != sha:
                raise ValueError('Corrupt object in publisher output')
        else:
            dest.write_bytes(content)
    temp = output / ('.' + manifest_name + '.tmp')
    temp.write_bytes(envelope)
    os.replace(temp, output / manifest_name)
    return envelope


def publish(source, output, key, version, sequence, lifetime=7 * 86400, channel=CHANNEL):
    if channel not in ALLOWED_CHANNELS:
        raise ValueError('Unsupported channel')
    source, output = Path(source).resolve(), Path(output).resolve()
    if output == source or source in output.parents:
        raise ValueError('Output must be outside source')
    entries = []
    blobs = {}
    for path in sorted(source.rglob('*')):
        assert_no_links(path)
        if path.is_dir():
            continue
        name = path.relative_to(source).as_posix()
        validate_path(name)
        content = path.read_bytes()
        sha = digest(content)
        entries.append({'path': name, 'sha256': sha, 'size': len(content)})
        blobs[sha] = content
    now = int(time.time())
    doc = {'schema': 1, 'app': APP, 'platform': PLATFORM, 'channel': channel,
           'version': version, 'sequence': sequence, 'issued_at': now,
           'expires_at': now + lifetime, 'files': entries}
    envelope = sign_document(doc, key)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    verify_manifest(envelope, public, channel=channel)
    return _write_objects(output, blobs, envelope, 'manifest.json')


def publish_launcher(exe_path, output, key, version, sequence, lifetime=7 * 86400, channel=CHANNEL):
    if channel not in ALLOWED_CHANNELS:
        raise ValueError('Unsupported channel')
    exe_path, output = Path(exe_path).resolve(), Path(output).resolve()
    assert_no_links(exe_path)
    content = exe_path.read_bytes()
    if len(content) < 64:
        raise ValueError('Launcher EXE too small')
    sha = digest(content)
    now = int(time.time())
    doc = {
        'schema': 1, 'app': APP, 'platform': PLATFORM, 'channel': channel, 'kind': 'launcher',
        'version': version, 'sequence': sequence, 'issued_at': now, 'expires_at': now + lifetime,
        'file': {'name': 'ZDECHLAK-Launcher.exe', 'size': len(content), 'sha256': sha},
    }
    envelope = sign_document(doc, key)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    verify_launcher_manifest(envelope, public, channel=channel)
    return _write_objects(output, {sha: content}, envelope, 'launcher-manifest.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    gen = sub.add_parser('keygen')
    gen.add_argument('--private', required=True)
    gen.add_argument('--public', required=True)
    build = sub.add_parser('manifest')
    build.add_argument('--source', required=True)
    build.add_argument('--output', required=True)
    build.add_argument('--private', required=True)
    build.add_argument('--version', required=True)
    build.add_argument('--sequence', type=int, required=True)
    build.add_argument('--channel', default=CHANNEL, choices=sorted(ALLOWED_CHANNELS))
    build.add_argument('--lifetime', type=int, default=31 * 86400)
    launch = sub.add_parser('launcher')
    launch.add_argument('--exe', required=True)
    launch.add_argument('--output', required=True)
    launch.add_argument('--private', required=True)
    launch.add_argument('--version', required=True)
    launch.add_argument('--sequence', type=int, required=True)
    launch.add_argument('--channel', default=CHANNEL, choices=sorted(ALLOWED_CHANNELS))
    launch.add_argument('--lifetime', type=int, default=31 * 86400)
    args = parser.parse_args()
    if args.command == 'keygen':
        generate_key(args.private, args.public)
        return
    key = serialization.load_pem_private_key(Path(args.private).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Ed25519 private key required')
    if args.command == 'manifest':
        publish(args.source, args.output, key, args.version, args.sequence,
                lifetime=args.lifetime, channel=args.channel)
    else:
        publish_launcher(args.exe, args.output, key, args.version, args.sequence,
                         lifetime=args.lifetime, channel=args.channel)


if __name__ == '__main__':
    main()
