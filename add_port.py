from scapy.all import *
import argparse
import sys

def add_port(ip, port_to_add, port):
    new_port = str(port_to_add)
    new_port = new_port.encode("utf-8")

    pkt = IP(dst=ip)/TCP(dport=port, flags="PA")/Raw(new_port)
    send(pkt, verbose=False)

    print "port sent and added"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", type=str, help="ip-addr destination where octopi is running")
    parser.add_argument("-n", type=int, help="port to add to whitelist of octopi")
    parser.add_argument("-p", type=int, help="toggling port")

    args = parser.parse_args()

    ip_addr = args.d
    new_port = args.n
    port = args.p

    if port < 0 or port > 65535:
        print "input valid toggle port number"
        sys.exit(1)

    if new_port < 0 or new_port > 65535:
        print "input valid new port number"
        sys.exit(1)

    add_port(ip_addr, new_port, port)
    
    sys.exit(0)
