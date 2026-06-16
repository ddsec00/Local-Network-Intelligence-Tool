import socket
import argparse

from sniffer import create_sniffer
from parser import (
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_tcp_segment,
    parse_udp_segment,
    get_service_name
)


# get command line options (--tcp / --udp)
def get_args():
    parser = argparse.ArgumentParser(description="Packet Sniffer")

    parser.add_argument("--tcp", action="store_true", help="show only TCP traffic")
    parser.add_argument("--udp", action="store_true", help="show only UDP traffic")

    return parser.parse_args()


# get your local machine IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


# check if packet is incoming or outgoing
def get_direction(src_ip, dst_ip, local_ip):
    if src_ip == local_ip:
        return "OUT"
    elif dst_ip == local_ip:
        return "IN"
    else:
        return "OTHER"


def main():
    args = get_args()

    sniffer = create_sniffer()
    local_ip = get_local_ip()

    print(f"Local IP: {local_ip}")
    print("Sniffer started...\n")

    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        eth = parse_ethernet_frame(raw_data)

        # ignore non-IP packets
        if eth["protocol"] != 2048:
            continue

        ip = parse_ipv4_packet(eth["payload"])

        direction = get_direction(
            ip["source_ip"],
            ip["destination_ip"],
            local_ip
        )

        # TCP packets
        if ip["protocol"] == 6:

            # skip if user only wants UDP
            if args.udp:
                continue

            tcp = parse_tcp_segment(ip["payload"])
            service = get_service_name(tcp["destination_port"])

            print(
                f"{direction} {service} TCP "
                f"{ip['source_ip']}:{tcp['source_port']} "
                f"→ {ip['destination_ip']}:{tcp['destination_port']}"
            )

        # UDP packets
        elif ip["protocol"] == 17:

            # skip if user only wants TCP
            if args.tcp:
                continue

            udp = parse_udp_segment(ip["payload"])
            service = get_service_name(udp["destination_port"])

            print(
                f"{direction} {service} UDP "
                f"{ip['source_ip']}:{udp['source_port']} "
                f"→ {ip['destination_ip']}:{udp['destination_port']}"
            )

        # everything else
        else:
            print(
                f"{direction} OTHER "
                f"{ip['source_ip']} → {ip['destination_ip']} "
                f"| Proto: {ip['protocol']}"
            )


if __name__ == "__main__":
    main()