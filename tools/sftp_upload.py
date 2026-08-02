#!/usr/bin/env python3
"""Upload a local file or directory tree to the Ubuntu dev box via SFTP.

Usage: python tools/sftp_upload.py <local_path> <remote_path>

Uses the same FWGRAPH_SSH_* environment variables and SSH-key/password prompt
behavior as remote_exec.py. Directories are uploaded recursively.
"""

from __future__ import annotations

import getpass
import os
import posixpath
import shlex
import sys

import paramiko


DEFAULT_HOST = "192.168.141.135"
DEFAULT_USER = "tankuku"


def _connect() -> paramiko.SSHClient:
    host = os.getenv("FWGRAPH_SSH_HOST", DEFAULT_HOST)
    user = os.getenv("FWGRAPH_SSH_USER", DEFAULT_USER)
    key_file = os.getenv("FWGRAPH_SSH_KEY")
    password = os.getenv("FWGRAPH_SSH_PASSWORD")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    options: dict[str, object] = {
        "hostname": host,
        "username": user,
        "timeout": 15,
        "allow_agent": True,
        "look_for_keys": True,
    }
    if key_file:
        options["key_filename"] = key_file
    if password:
        options["password"] = password

    try:
        client.connect(**options)
    except paramiko.AuthenticationException:
        if password or not sys.stdin.isatty():
            raise
        options["password"] = getpass.getpass(f"SSH password for {user}@{host}: ")
        client.connect(**options)
    return client


def mkdir_p(client: paramiko.SSHClient, path: str) -> None:
    channel = client.get_transport().open_session()
    try:
        channel.exec_command(f"mkdir -p -- {shlex.quote(path)}")
        rc = channel.recv_exit_status()
        if rc != 0:
            raise RuntimeError(f"remote mkdir failed with exit code {rc}: {path}")
    finally:
        channel.close()


def upload(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    local: str,
    remote: str,
) -> None:
    if os.path.isfile(local):
        mkdir_p(client, posixpath.dirname(remote))
        sftp.put(local, remote)
        print(f"  {local} -> {remote}")
        return

    for root, _dirs, files in os.walk(local):
        rel = os.path.relpath(root, local)
        remote_dir = remote if rel == "." else posixpath.join(
            remote, rel.replace(os.sep, "/")
        )
        mkdir_p(client, remote_dir)
        for filename in files:
            local_path = os.path.join(root, filename)
            remote_path = posixpath.join(remote_dir, filename)
            sftp.put(local_path, remote_path)
            print(f"  {local_path} -> {remote_path}")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: sftp_upload.py <local_path> <remote_path>", file=sys.stderr)
        return 2
    local, remote = sys.argv[1], sys.argv[2]
    if not os.path.exists(local):
        print(f"local path does not exist: {local}", file=sys.stderr)
        return 2

    client = _connect()
    try:
        sftp = client.open_sftp()
        try:
            upload(client, sftp, local, remote)
        finally:
            sftp.close()
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
