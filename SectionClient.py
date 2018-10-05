#!/usr/bin/env python3

import sys
import socket
import hashlib

PORT = 7037

# per <https://en.wikipedia.org/wiki/User_Datagram_Protocol>
MAX_UDP_PAYLOAD = 65507


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
    section_info = {}

    for line in lines:
        columns = line.split(maxsplit=3)

        section = int(columns[0])
        size = int(columns[1])
        digest = columns[2]

        sections.add(section)
        section_info[section] = {'size': size, 'digest': digest}

    return file_digest, sections, section_info


def download_section(n, hostname):
    response = send_message(f'SECTION {n}', hostname)
    return response


def usage(program):
    sys.exit(f'Usage: python3 {program} [HOST] [FILE] ')


def main(hostname, filename):
    expected_file_digest, sections, section_info = list_sections(hostname)

    file_contents = bytearray()
    for i in sections:
        expected = section_info[i]
        expected_size = expected['size']
        expected_digest = expected['digest']

        print(f'section {i}...', end='')
        data = download_section(i, hostname)
        size = len(data)
        digest = md5(data)

        if size != expected_size:
            print(f'size {size}, expected {expected_size}')
        elif digest != expected_digest:
            print(f'digest {digest}, expected {expected_digest}')
        else:
            file_contents.extend(data)
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
