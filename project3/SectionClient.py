#!/usr/bin/env python3

import os
import sys
import errno
import socket
import hashlib
import platform
import itertools
import selectors

DEFAULT_PORT = 7037

SIZE_1_KiB = 1024
SIZE_32_KiB = 32 * SIZE_1_KiB

WINDOWS = (platform.system() == 'Windows')
IN_PROGRESS = errno.WSAEWOULDBLOCK if WINDOWS else errno.EINPROGRESS


class Section:
    MAX_SECTION_SIZE = SIZE_32_KiB

    def __init__(self, num, size, digest):
        self.num = int(num)
        self.size = int(size)
        self.digest = digest
        self.from_byte = self.num * self.MAX_SECTION_SIZE
        self.to_byte = (self.num + 1) * self.MAX_SECTION_SIZE
        self.data = bytearray()
        self.request_sent = False

    def check_integrity(self):
        size = len(self.data)
        digest = md5(self.data)

        ok = True
        if size != self.size:
            print(f'size {size}, expected {self.size}')
            ok = False
        elif digest != self.digest:
            print(f'digest {digest}, expected {self.digest}')
            ok = False

        return ok


def md5(data):
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def parse_address(addr):
    components = addr.split(':', maxsplit=1)
    hostname = components[0]
    port = DEFAULT_PORT if len(components) == 1 else int(components[1])

    return (hostname, port)


def recv_until_close(client_socket):
    data = bytearray()

    buffer = client_socket.recv(SIZE_1_KiB)
    while buffer:
        data.extend(buffer)
        buffer = client_socket.recv(SIZE_1_KiB)

    return data


def list_sections(client_socket):
    client_socket.sendall('LIST'.encode())
    response = recv_until_close(client_socket)

    lines = response.decode().splitlines()

    file_digest = lines.pop(0)
    sections = set()
    total_size = 0

    for line in lines:
        columns = line.split(maxsplit=2)

        s = Section(*columns)
        sections.add(s)
        total_size += s.size

    return file_digest, sections, total_size


def usage(program):
    sys.exit(f'Usage: python3 {program} FILE HOST[:PORT]...')


def main(filename, *addresses):
    server_addresses = [parse_address(addr) for addr in addresses]
    servers = itertools.cycle(server_addresses)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(next(servers))
        expected_file_digest, sections, total_size = list_sections(s)

    file_contents = bytearray(total_size)

    with selectors.DefaultSelector() as sel:
        for section in sections:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            err = s.connect_ex(next(servers))
            if err != IN_PROGRESS:
                print(f'connect_ex returned {err}: {os.strerror(err)}')
                return err
            sel.register(s, selectors.EVENT_READ | selectors.EVENT_WRITE, section)

        # TODO: use sel to multiplex socket I/O

    file_digest = md5(file_contents)
    if file_digest != expected_file_digest:
        print(f'{filename}: digest {file_digest}, expected {expected_file_digest}')
    else:
        with open(filename, 'wb') as f:
            f.write(file_contents)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage(sys.argv[0])

    sys.exit(main(*sys.argv[1:]))
