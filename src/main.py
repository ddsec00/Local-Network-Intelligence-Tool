import socket
import argparse
import time

from sniffer import create_sniffer
from parser import (
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_tcp_segment,
    parse_udp_segment,
    get_service_name
)


# read command line options like --tcp / --udp
def get_args():
    parser = argparse.ArgumentParser(description="Packet Sniffer")

    parser.add_argument("--tcp", action="store_true", help="show only TCP traffic")
    parser.add_argument("--udp", action="store_true", help="show only UDP traffic")

    return parser.parse_args()


# figure out what IP this machine is using
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # fake connection just to let OS pick the right interface
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


# check if packet is going in or out of this machine
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

    # simple counters so we can see traffic stats
    total_packets = 0
    tcp_count = 0
    udp_count = 0
    other_count = 0

    last_print = time.time()

    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        total_packets += 1

        eth = parse_ethernet_frame(raw_data)

        # ignore anything that's not IPv4
        if eth["protocol"] != 2048:
            continue

        ip = parse_ipv4_packet(eth["payload"])

        direction = get_direction(
            ip["source_ip"],
            ip["destination_ip"],
            local_ip
        )

        # ---------------- TCP traffic ----------------
        if ip["protocol"] == 6:

            # if user only wants UDP, skip TCP
            if args.udp:
                continue

            tcp_count += 1

            tcp = parse_tcp_segment(ip["payload"])
            service = get_service_name(tcp["destination_port"])

            print(
                f"{direction} {service} TCP "
                f"{ip['source_ip']}:{tcp['source_port']} "
                f"→ {ip['destination_ip']}:{tcp['destination_port']}"
            )

        # ---------------- UDP traffic ----------------
        elif ip["protocol"] == 17:

            # if user only wants TCP, skip UDP
            if args.tcp:
                continue

            udp_count += 1

            udp = parse_udp_segment(ip["payload"])
            service = get_service_name(udp["destination_port"])

            print(
                f"{direction} {service} UDP "
                f"{ip['source_ip']}:{udp['source_port']} "
                f"→ {ip['destination_ip']}:{udp['destination_port']}"
            )

        # anything else we don't explicitly handle
        else:
            other_count += 1

        # every 5 seconds, show a quick summary of what’s happening
        if time.time() - last_print > 5:
            print("\n--- STATS ---")
            print(f"Total packets: {total_packets}")
            print(f"TCP: {tcp_count}")
            print(f"UDP: {udp_count}")
            print(f"OTHER: {other_count}")
            print("-------------\n")

            last_print = time.time()


if __name__ == "__main__":
    main()