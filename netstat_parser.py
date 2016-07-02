#!/usr/bin/env  python2

import argparse



def is_valid_ip4(ip):
    # some rudimentary checks if ip is actually a valid IP
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    return octets[0] != 0 and all(0 <= int(octet) <= 255 for octet in octets)


def parse_args():
    parser = argparse.ArgumentParser(description='Simple TCP proxy for data ' +
                                                 'interception and ' +
                                                 'modification. ' +
                                                 'Select modules to handle ' +
                                                 'the intercepted traffic.')

    parser.add_argument('-os', '--os', dest='operating_system', required=False,
                        help='win/linux')

    parser.add_argument('-f', '--file', dest='file_name', required=True,
                        help='File to parse')

    parser.add_argument('-o', '--out', dest='output_format', required=False,
                        help='Option for output format: nmap')


    return parser.parse_args()


def parse_linux(file_content):

    port_list = []

    for line in file_content:
        if "LISTEN" in line:
            for entry in line.split(' '):
                #get port and append to list
                if ':' in entry and is_valid_ip4(entry.split(':')[0]) and '*' not in entry.split(':')[1]:
                    port_list.append(entry.split(':')[1])

    return port_list


def parse_windows(file_content):

    port_list = []

    for line in file_content:
        print line
        if "LISTEN" in line or "ABH" in line:
            for entry in line.split(' '):
                if ':' in entry and is_valid_ip4(entry.split(':')[0]) and '0' not in entry.split(':')[1]:
                    port_list.append(entry.split(':')[1])

    return port_list


def main():


    args = parse_args()
    file_content = open(args.file_name, 'r').readlines()

    port_list = []
    if args.operating_system is None:
        print '[+] No operating system given. Will try to find out'

        if 'Aktive Verbindungen' in file_content[0]:
            print '[+] Guessing Windows'
            port_list = parse_windows(file_content)
        else:
            print '[+] Guessing Linux'
            port_list = parse_linux(file_content)

    elif:
        if "linux" in args.operating_system:
             port_list = parse_linux(file_content)
        elif "win" in args.operating_system:
             port_list = parse_linux(file_content)

    if args.output_format is not None:
        if 'nmap' in args.output_format:
            s = '-p'
            for port in port_list:
                s += str(port) + ','
            else:
                s += str(port)
            print s

    else:
        for port in port_list:
            print port


main()