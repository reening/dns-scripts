#!/usr/bin/env python3

import base64
import hashlib
import socket
import sys

import paramiko


SSHFP_KEY_TYPES = {
    'ssh-rsa': 1,
    'ssh-dss': 2,
    'ecdsa-sha2-nistp256': 3,
    'ssh-ed25519': 4,
}


def get_host_key(hostname, key_type):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, 22))

    transport = paramiko.Transport(sock)

    opts = transport.get_security_options()
    opts.key_types = [key_type]

    sys.stderr = None

    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        sock.close()
        return

    key = transport.get_remote_server_key()

    transport.close()
    sock.close()

    name = key.get_name()
    data = key.asbytes()

    key_type = SSHFP_KEY_TYPES.get(name)

    h = hashlib.sha1()
    h.update(data)
    hash_type = 1
    hash_data = h.hexdigest().upper()

    rr = '{} SSHFP {} {} {}'.format(
        hostname,
        key_type,
        hash_type,
        hash_data,
    )

    print(rr)

    h = hashlib.sha256()
    h.update(data)
    hash_type = 2
    hash_data = h.hexdigest().upper()

    rr = '{} SSHFP {} {} {}'.format(
        hostname,
        key_type,
        hash_type,
        hash_data,
    )

    print(rr)


def main():
    if len(sys.argv) != 2:
        print('Usage: {} hostname'.format(sys.argv[0]))
        exit(1)

    hostname = sys.argv[1]

    for key_type in SSHFP_KEY_TYPES.keys():
        get_host_key(hostname, key_type)


if __name__ == '__main__':
    main()
