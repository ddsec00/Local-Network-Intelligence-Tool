import socket


def create_sniffer(interface=None):
    
    sniffer = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(0x0003)
    )

    
    if interface:
        sniffer.bind((interface, 0))

    return sniffer

