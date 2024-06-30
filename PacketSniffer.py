from scapy.all import sniff, wrpcap


def packet_callback(packet):
    if packet.haslayer("IP"):
        print(packet.summary())


def main():
    print("Starting packet sniffer...")
    packets = sniff(filter="ip", prn=packet_callback, count=50)
    wrpcap('captured_packets.pcap', packets)


if __name__ == "__main__":
    main()
