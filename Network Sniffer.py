from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

if __name__ == "__main__":
    print("Starting network sniffer...")
    sniff(prn=packet_callback, store=False, count=10)
