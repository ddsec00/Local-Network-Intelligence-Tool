import struct


def format_mac(mac):
    return ':'.join('%02x' % b for b in mac)


def format_ip(addr):
    return '.'.join(map(str, addr))


def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", data[:14])

    return {
        "destination_mac": format_mac(dest_mac),
        "source_mac": format_mac(src_mac),
        "protocol": proto,
        "payload": data[14:]
    }


def parse_ipv4_packet(data):
    version_header_length = data[0]

    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, dst = struct.unpack(
        "!8x B B 2x 4s 4s",
        data[:20]
    )

    return {
        "version": version,
        "header_length": header_length,
        "ttl": ttl,
        "protocol": proto,
        "source_ip": format_ip(src),
        "destination_ip": format_ip(dst),
        "payload": data[header_length:]
    }


def parse_tcp_segment(data):
    src_port, dst_port = struct.unpack("!HH", data[:4])

    return {
        "source_port": src_port,
        "destination_port": dst_port,
        "payload": data[20:]  # TCP header is usually 20 bytes
    }


def parse_udp_segment(data):
    src_port, dst_port, length = struct.unpack("!HHH", data[:6])

    return {
        "source_port": src_port,
        "destination_port": dst_port,
        "length": length,
        "payload": data[8:]
    }
def get_service_name(port):
        common_ports = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            21: "FTP",
        }
        return common_ports.get(port, str(port))

def parse_icmp_packet(data):
    icmp_type, icmp_code, checksum = struct.unpack("!BBH", data[:4])

    return{
        "type": icmp_type,
        "code": icmp_code,
        "checksum": checksum,
        "payload": data[4:]
    }

# extract domain name from a DNS query packet
def parse_dns_query(data):
    try:
        domain_parts = []

        # DNS header is always 12 bytes
        position = 12

        while True:
            length = data[position]

            # length 0 means end of domain name
            if length == 0:
                break

            position += 1

            domain_parts.append(
                data[position:position + length].decode()
            )

            position += length

        return ".".join(domain_parts)

    except:
        return None