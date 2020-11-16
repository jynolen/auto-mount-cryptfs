#!/usr/bin/env python3

import sys
import os
import argparse
import logging
import logging.handlers
import hashlib
import binascii
import json
import tempfile
import subprocess
import pwd
from pathlib import Path

import psutil
import paramiko
from paramiko import RSAKey, DSSKey, Ed25519Key
from pythonjsonlogger import jsonlogger

logger = logging.getLogger("gocryptfs_handler")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.ERROR)
formatter = jsonlogger.JsonFormatter()
handler.setFormatter(formatter)
logger.addHandler(handler)


handler = logging.FileHandler('/var/log/ssh_mount.log')
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)

def cli():
    def volume(astring):
        return Path(astring)

    parser = argparse.ArgumentParser(prog='personnal_ssh_luks')
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"], default="INFO")
    parser.add_argument("--volume", type=volume, required=True)

    _ = parser.add_argument("--spec-file", type=volume, default=Path.home().joinpath(".ssh_volume"))
    subparsers = parser.add_subparsers(help='sub-command help', required=True, dest="subparser")

    unlock_parser = subparsers.add_parser('unlock', help='unlock help')
    _ = subparsers.add_parser('passphrase', help='passphrase help')

    init_parser = subparsers.add_parser('init', help='init help')
    init_parser.add_argument("--key-filter", type=str, required=True)

    unlock_parser.add_argument("--target", type=volume, required=True)
    unlock_parser.add_argument("--skip", action="store_true", required=False, default=True)
    unlock_parser.add_argument("--idle", action="store", type=int, required=False, default=3600)

    unmount = subparsers.add_parser('unmount', help='unlock help')
    return parser.parse_args()

def select_ssh_key(_filter):
    def create_full_key(key):
        _key = None
        data = os.urandom(32)
        for sshtype in [ RSAKey, DSSKey, Ed25519Key ]:
            try:
                _key = sshtype(data=key.asbytes())
                _key.agent = key.agent
                _key.sign_ssh_data = key.sign_ssh_data
                assert _key.verify_ssh_sig(data=data, msg=paramiko.Message(_key.sign_ssh_data(data=data)))
                fingerprints = []
                khex = _key.asbytes()
                for _hash in [ hashlib.md5, hashlib.sha256, hashlib.sha512 ]:
                    _hex = _hash(khex).hexdigest()
                    fingerprints.append(_hex)
                    fingerprints.append(":".join(_hex[i:i+2] for i in range(0, len(_hex), 2)))
                return _key, fingerprints
            except paramiko.SSHException:
                continue
        return None , []
    match = set()
    keys = [ create_full_key(k) for k in paramiko.agent.Agent().get_keys() ]
    for key_, fingerprints in keys:
        for fingerprint in fingerprints:
            if _filter in fingerprint:
                match.add(key_)

    if len(match) > 1:
        raise ValueError("Too much key that match filter have been found")
    if len(match) == 0:
        raise ValueError("Key that match filter have not been found")
    return match.pop()

def generate_passphrase():
    hash_digest = hashlib.sha512(os.urandom(1024)).digest()
    for _ in range(0, 1024):
        hash_digest = hashlib.sha512(hash_digest).digest()
    return hashlib.sha512(hash_digest).digest()

def generate_ssh_passphrase(passphrase, key):
    hash_digest = key.sign_ssh_data(passphrase)
    for _ in range(0, 1024):
        hash_digest = hashlib.sha512(hash_digest).digest()
    return hash_digest

def get_volume_passphrase(spec_file, volume):
    if not spec_file.exists():
        raise ValueError("Spec File not exists")

    passphrase = None
    key = None
    try:
        value = str(volume.absolute())
        current_spec = json.load(open(spec_file, "r"))
        key = current_spec.get(value)["sshkey"]
        passphrase = binascii.a2b_base64(current_spec.get(value)["passphrase"])
        sshkey = select_ssh_key(binascii.hexlify(binascii.a2b_base64(key)).decode())
    except Exception as exception:
        raise ValueError("Unenable to retreive ssh key and passphrase") from exception

    return binascii.hexlify(generate_ssh_passphrase(passphrase, sshkey)).decode()

def initialize_volume(volume, _filter, spec_file):
    if volume.joinpath("gocryptfs.conf").exists():
        logger.warning("Cannot init volume", extra={"volume": volume, "reason": "init_done"})
        return 1

    current_spec = json.load(open(spec_file, "r")) if spec_file.exists() else {}

    key = select_ssh_key(_filter)
    passphrase = generate_passphrase()
    ssh_passphrase = binascii.hexlify(generate_ssh_passphrase(passphrase, key)).decode()

    _spec = {
        "volume": volume.absolute().__str__(),
        "passphrase": binascii.b2a_base64(passphrase, newline=False).decode(),
        "sshkey": binascii.b2a_base64(key.get_fingerprint(), newline=False).decode(),
    }

    current_spec[volume.absolute().__str__()] = _spec
    with open(spec_file, "w") as file_write:
        json.dump(fp=file_write, obj=current_spec)
    assert get_volume_passphrase(spec_file, volume) == ssh_passphrase

    python_exec, python_script =  sys.executable, str(Path(__file__).absolute())
    gocryptfs_cli = ["gocryptfs"]
    for _args in [ python_exec, python_script, "--volume", str(volume.absolute()), "passphrase" ]:
        gocryptfs_cli.append("-extpass")
        gocryptfs_cli.append(_args)
    gocryptfs_cli.append("-init")
    gocryptfs_cli.append(str(volume.absolute()))

    try:
        output = subprocess.run(gocryptfs_cli, capture_output=True, check=True)
        logger.info("Volume Init", extra={"tools.stdout":output.stdout.decode(), "tools.stderr":output.stderr.decode(), "volume": volume, "key": binascii.hexlify(key.get_fingerprint())})
    except subprocess.CalledProcessError as exception:
        logger.error("Tools error", extra={"tools.stdout":exception.stdout.decode(), "tools.stderr":exception.stderr.decode()})
        return 2

def unlock_volume(spec_file, volume, target, cli_args):
    partitions = [ p for p in psutil.disk_partitions(all=True) if p.device == str(volume) or p.mountpoint == target]
    if len(partitions) > 0:
        logger.warning("Cannot unlock volume", extra={"volume": volume, "reason": "mounted_done"})
        return 1

    python_exec, python_script =  sys.executable, str(Path(__file__).absolute())
    gocryptfs_cli = ["gocryptfs"]

    for _args in [  python_exec, python_script, "--spec-file",
                    str(spec_file.absolute()),  "--volume", str(volume.absolute()), "passphrase" ]:
        gocryptfs_cli.append("-extpass")
        gocryptfs_cli.append(_args)

    if args.idle > 0:
        gocryptfs_cli.append("-idle")
        gocryptfs_cli.append(f"{cli_args.idle}s")

    gocryptfs_cli.append(str(volume.absolute()))
    gocryptfs_cli.append(str(target.absolute()))

    try:
        subprocess.run(gocryptfs_cli, capture_output=True, check=True)
        logger.info("Unlock volume", extra={"volume": volume})
    except subprocess.CalledProcessError as exception:
        logger.error("Tools error", extra={"tools.stdout":exception.stdout.decode(), "tools.stderr":exception.stderr.decode()})
        return 2

    return 0

def unmount_volume(user):
    if user is None:
        return 0
    if user in set([u.name for u in psutil.users()]):
        logger.info("Not unmounting volume", extra={"user": user, "reason":"still_logged_in"})
        return 0

    uid = pwd.getpwnam(user).pw_uid
    partitions = [ p for p in psutil.disk_partitions(all=True)
                                if p.fstype == "fuse.gocryptfs" and  f"user_id={uid}" in p.opts ]

    try:
        for volume in partitions:
            subprocess.run(["fusermount", "-u", volume.mountpoint], capture_output=True, check=True)
            logger.info("Volume unmounted", extra={"volume": volume.mountpoint})
        return 0
    except subprocess.CalledProcessError as exception:
        logger.error(exception.stderr.decode())


if __name__ == "__main__":
    args = cli()
    logging.getLogger().handlers.clear()
    handler.setLevel(getattr(logging, args.log_level))
    ret = 0
    if args.subparser == "init":
        ret = initialize_volume(args.volume, args.key_filter, args.spec_file)

    elif args.subparser == "passphrase":
        ret = print(get_volume_passphrase(args.spec_file, args.volume))

    elif args.subparser == "unlock":
        ret = unlock_volume(args.spec_file, args.volume, args.target, args)

    elif args.subparser == "unmount":
        if os.environ.get("PAM_TYPE") == "close_session":
            ret = unmount_volume(os.environ.get("PAM_USER"))

    sys.exit(ret)
 ✔ ⚡ root@vps  /var/l
