import struct 
def format_mac(mac):
    return ':'.join('%02x' % b for b in mac)

def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        "destination_mac": format_mac(dest_mac),
        "source_mac": format_mac(src_mac),
        "protocol": proto
    }    