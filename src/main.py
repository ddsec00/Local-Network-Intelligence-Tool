from sniffer import create_sniffer
from parser import (
    parse_ethernet_frame,
    parse_ipv4_packet,
    parse_tcp_segment,
    parse_udp_segment
)


def main():
    sniffer = create_sniffer()

    print("Packet sniffer started...")

    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        eth = parse_ethernet_frame(raw_data)

        # IPv4 packets only
        if eth["protocol"] == 2048:

            ip = parse_ipv4_packet(eth["payload"])

            # ICMP (Ping)
            if ip["protocol"] == 1:
                print(
                    f"ICMP {ip['source_ip']} → {ip['destination_ip']}"
                )

            # TCP
            elif ip["protocol"] == 6:
                tcp = parse_tcp_segment(ip["payload"])

                print(
                    f"TCP {ip['source_ip']}:{tcp['source_port']} "
                    f"→ {ip['destination_ip']}:{tcp['destination_port']}"
                )

            # UDP
            elif ip["protocol"] == 17:
                udp = parse_udp_segment(ip["payload"])

                print(
                    f"UDP {ip['source_ip']}:{udp['source_port']} "
                    f"→ {ip['destination_ip']}:{udp['destination_port']}"
                )

            # Any other IP protocol
            else:
                print(
                    f"IP {ip['source_ip']} → {ip['destination_ip']} "
                    f"| Proto: {ip['protocol']}"
                )

        # Non-IPv4 Ethernet frames
        else:
            print(
                f"Ethernet | {eth['source_mac']} → {eth['destination_mac']} "
                f"| Proto: {eth['protocol']}"
            )


if __name__ == "__main__":
    main()