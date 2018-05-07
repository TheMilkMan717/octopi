from scapy.all import *
import argparse
import sys

off_banner = b"EASTER BUNNY'S FLUFFY WHITE COCK"
on_banner = b"CAESAR SALAD COCK"

def toggle(ip, banner, port):
    pkt = IP(dst=ip)/TCP(dport=port, flags="PA")/Raw(banner)
    send(pkt, verbose=False)
    if banner == off_banner:
        print "toggled off"
    else:
        print "toggled on"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", type=str, help="ip-addr destination where octopi is running")
    parser.add_argument("--off", default=False, action="store_true", help="toggle octopi to turn off")
    parser.add_argument("--on", default=False, action="store_true",  help="toggle octopi to turn on")
    parser.add_argument("-p", type=int, help="toggling port")

    args = parser.parse_args()

    ip_addr = args.d
    port = args.p

    if port < 0 or port > 65535:
        print "input valid port number"
        sys.exit(1)

    # if toggle off
    if args.off:
        toggle(ip_addr, off_banner, port)
    # if toggle on
    else:
        toggle(ip_addr, on_banner, port)

    sys.exit(0)
