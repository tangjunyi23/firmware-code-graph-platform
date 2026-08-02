#!/usr/bin/env python3
"""Run a command on the remote Ubuntu dev box via SSH.

Usage: python tools/remote_exec.py "<command>"

Connection settings come from FWGRAPH_SSH_HOST, FWGRAPH_SSH_USER,
FWGRAPH_SSH_KEY, and FWGRAPH_SSH_PASSWORD. If neither a key nor a password is
configured, Paramiko first tries the local SSH agent and standard key files,
then prompts for a password when running interactively.
"""

from __future__ import annotations

import getpass
import os
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


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 2:
        print('usage: remote_exec.py "<command>"', file=sys.stderr)
        return 2

    client = _connect()
    try:
        stdin, stdout, stderr = client.exec_command(sys.argv[1], timeout=280)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
    finally:
        client.close()

    if out:
        print(out, end="")
    if err:
        print(err, end="", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
