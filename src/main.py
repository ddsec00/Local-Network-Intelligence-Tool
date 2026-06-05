from sniffer import create_sniffer
from parser import parse_ethernet_frame


def main():
    # CHANGE THIS if needed: "eth0", "wlan0", "enp0s3"
    interface = "eth0"

    sniffer = create_sniffer(interface)

    print(f"Packet sniffer started on {interface}...")

    while True:
        raw_data, addr = sniffer.recvfrom(65535)

        eth = parse_ethernet_frame(raw_data)

        print(
            f"Src MAC: {eth['source_mac']} → "
            f"Dst MAC: {eth['destination_mac']} | "
            f"Proto: {eth['protocol']} | "
            f"Size: {len(raw_data)} bytes"
        )


if __name__ == "__main__":
    main()