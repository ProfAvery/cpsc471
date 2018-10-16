#!/usr/bin/env python3

import sys
import socket
import hashlib

PORT = 7037

SIZE_1_KiB = 1024
SIZE_32_KiB = 32 * SIZE_1_KiB

# per <https://en.wikipedia.org/wiki/User_Datagram_Protocol>
MAX_UDP_PAYLOAD = 65507


class Section:
    MAX_SECTION_SIZE = SIZE_32_KiB

    def __init__(self, num, size, digest):
        self.num = int(num)
        self.size = int(size)
        self.digest = digest
        self.from_byte = self.num * self.MAX_SECTION_SIZE
        self.to_byte = (self.num + 1) * self.MAX_SECTION_SIZE


def md5(data):
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def send_message(message, hostname):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(message.encode(), (hostname, PORT))
        data, _ = s.recvfrom(MAX_UDP_PAYLOAD)

    return data


def list_sections(hostname):
    response = send_message('LIST', hostname)
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


def download_section(n, hostname):
    response = send_message(f'SECTION {n}', hostname)
    return response


def usage(program):
    sys.exit(f'Usage: python3 {program} [HOST] [FILE] ')


def main(hostname, filename):
    expected_file_digest, sections, total_size = list_sections(hostname)
    file_contents = bytearray(total_size)

    for section in sections:
        print(f'section {section.num}...', end='')

        data = download_section(section.num, hostname)
        size = len(data)
        digest = md5(data)

        if size != section.size:
            print(f'size {size}, expected {section.size}')
        elif digest != section.digest:
            print(f'digest {digest}, expected {section.digest}')
        else:
            file_contents[section.from_byte:section.to_byte] = data
            print('ok')

    file_digest = md5(file_contents)
    if file_digest != expected_file_digest:
        print(f'{filename}: digest {file_digest}, expected {expected_file_digest}')
    else:
        with open(filename, 'wb') as f:
            f.write(file_contents)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage(sys.argv[0])

    sys.exit(main(*sys.argv[1:]))
