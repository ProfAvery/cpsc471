#!/usr/bin/env python3

import sys
import math
import socket
import random
import hashlib
import datetime

UNRELIABLE = True

DEFAULT_PORT = 7037

SIZE_1_KiB = 1024
SIZE_32_KiB = 32 * SIZE_1_KiB

LARGEST_REQUEST = 'SECTION XXXX\n'
MAX_REQUEST_SIZE = len(LARGEST_REQUEST.encode())


class SectionedFile:
    MAX_SECTIONS = 1024
    MAX_SECTION_SIZE = SIZE_32_KiB
    MAX_FILE_SIZE = MAX_SECTIONS * MAX_SECTION_SIZE

    def __init__(self, filename):
        with open(filename, 'rb') as f:
            self.data = bytearray(f.read())

        if len(self.data) > self.MAX_FILE_SIZE:
            sys.exit(f'{filename}: file larger than {self.MAX_FILE_SIZE} bytes')

    def __len__(self):
        return math.ceil(len(self.data) / self.MAX_SECTION_SIZE)

    def __getitem__(self, key):
        if key >= self.MAX_SECTIONS:
            raise IndexError('section index out of range')

        from_byte = key * self.MAX_SECTION_SIZE
        to_byte = (key + 1) * self.MAX_SECTION_SIZE

        section = self.data[from_byte:to_byte]

        if from_byte >= len(self.data):
            raise IndexError('section index out of range')

        return section


def coin_flip():
    return random.choice([UNRELIABLE, False])


def corrupt(section):
    index = random.randrange(len(section))
    value = random.randint(0, 255)
    section[index] = value


def error(message):
    payload = f'ERROR: {message}\n'
    return payload.encode()


def md5(data):
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def list_sections(file):
    sections = []
    sections.append(md5(file.data))
    for index, section in enumerate(file):
        size = len(section)
        digest = md5(section)
        sections.append(f'{index} {size} {digest}')
    return '\n'.join(sections).encode()


def log(message):
    print(f'[{datetime.datetime.now()}] {message}')


def usage(program):
    sys.exit(f'Usage: python3 {program} FILE [PORT]')


def main(filename, port=DEFAULT_PORT):
    file = SectionedFile(filename)
    address = ('', int(port))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(address)
    server_socket.listen()

    client_socket, _ = server_socket.accept()
    while True:
        data = client_socket.recv(MAX_REQUEST_SIZE)
        request = data.decode().strip()

        accept_next = True
        if request:
            log(request)

            if request == 'LIST':
                payload = list_sections(file)
            elif request.startswith('SECTION'):
                if coin_flip():
                    client_socket.shutdown(socket.SHUT_RD)
                n = -1
                components = request.split(maxsplit=1)
                section = components[n]
                try:
                    n = int(section)
                except ValueError as e:
                    payload = error(e)
                if n < 0 or n >= len(file):
                    payload = error(f"invalid section index '{section}'")
                else:
                    payload = file[n]
                    if coin_flip():
                        corrupt(payload)
                    accept_next = False
            else:
                payload = error(f"unrecognized request '{request}'")

            client_socket.sendall(payload)

        if accept_next:
            client_socket.close()
            client_socket, _ = server_socket.accept()


if __name__ == '__main__':
    argc = len(sys.argv)
    if argc < 2 or argc > 3:
        usage(sys.argv[0])

    sys.exit(main(*sys.argv[1:]))
