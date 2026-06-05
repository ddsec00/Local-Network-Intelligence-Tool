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