from sniffer import create_sniffer
from parser import parse_ethernet_frame

def main():
    sniffer = create_sniffer()
    print("Packet sniffer started...")
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
    