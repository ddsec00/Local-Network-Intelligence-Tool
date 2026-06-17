import socket
import argparse
import time
from collections import Counter
from sniffer import create_sniffer
from parser import (
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_tcp_segment,
    parse_udp_segment,
    get_service_name
)


# just reading flags like --tcp or --udp from terminal
def get_args():
    parser = argparse.ArgumentParser(description="Packet Sniffer")

    parser.add_argument("--tcp", action="store_true", help="show only TCP traffic")
    parser.add_argument("--udp", action="store_true", help="show only UDP traffic")

    return parser.parse_args()


# figuring out what IP this machine is using
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # fake connection just to let OS pick correct interface
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


# figuring out if packet is coming in or going out
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
    print("Sniffer running...\n")

    # just counters so we can see traffic summary later
    total_packets = 0
    tcp_count = 0
    udp_count = 0
    other_count = 0
    # keep track of who talks the most
    top_sources = Counter()
    top_destinations = Counter()

    last_print = time.time()

    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        total_packets += 1  # count every packet we see

        eth = parse_ethernet_frame(raw_data)

        # ignore anything that's not IPv4 (we don’t care for now)
        if eth["protocol"] != 2048:
            continue

        ip = parse_ipv4_packet(eth["payload"])
        top_sources[ip["source_ip"]] += 1
        top_destinations[ip["destination_ip"]] += 1

        direction = get_direction(
            ip["source_ip"],
            ip["destination_ip"],
            local_ip
        )

        # ---------------- TCP ----------------
        if ip["protocol"] == 6:

            # if user only wants UDP, skip this
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

        # ---------------- UDP ----------------
        elif ip["protocol"] == 17:

            # if user only wants TCP, skip this
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

        # anything else we don’t fully handle yet
        else:
            other_count += 1

        # every 5 seconds, just show a quick summary
        if time.time() - last_print >= 5:
            print("\n--- STATS ---")
            print(f"Total packets: {total_packets}")
            print(f"TCP: {tcp_count}")
            print(f"UDP: {udp_count}")
            print(f"OTHER: {other_count}")
            print("-------------\n")

            print("\nTop Source IPs:")
            for ip, count in top_sources.most_common(5):
                print(f"  {ip}: {count}")

            print("\nTop Destination IPs:")
            for ip, count in top_destinations.most_common(5):
                print(f"  {ip}: {count}")

            print("-------------\n")
            last_print = time.time()

if __name__ == "__main__":
    main()