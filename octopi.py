#!/usr/bin/python

from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import sys
import os


def spoof_scan(packet):
    try:
        pkt = IP(packet.get_payload())

        # if it's not a TCP packet, let it through
        if not pkt.haslayer(TCP):
            packet.accept()
            return

        # if it's not a SYN packet
        tcp_flag = pkt.sprintf("%TCP.flags%")
        if tcp_flag == "S":
            # uncomment to set specific ports to allow through
            # if pkt["TCP"].dport == 8000:
            #     packet.accept()
            #     return
            # spoof the fake reply
            ret_pkt = IP(src=pkt["IP"].dst, dst=pkt["IP"].src, ttl=pkt["IP"].ttl - 1)/ \
                    TCP(dport=pkt["TCP"].sport, sport=pkt["TCP"].dport, seq=1234, ack=pkt["TCP"].seq + 1, flags="SA")

            packet.drop()
            print "Scan:\t%d" % ret_pkt["TCP"].sport
            send(ret_pkt, verbose=False)

        else:
            packet.accept()
        

    except Exception as e:
        print e
        print "ERROR"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # parser.add_argument("", type=str)
    args = parser.parse_args()


    try:
        # os.system("iptables -A OUTPUT -p tcp --sport 1:65535 --tcp-flags RST RST -j DROP")
        os.system("iptables -A INPUT -p tcp -j NFQUEUE --queue-num 1")
        # os.system("iptables -D OUTPUT -p tcp --sport 1:65535 --tcp-flags RST RST -j DROP")
        print "UPDATED IPTABLES..."

        nfqueue = NetfilterQueue()
        # 1 is iptables rule queue number, filter_get_requests is callback function
        print "CREATED NFQUEUE..."
        nfqueue.bind(1, spoof_scan)
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()
        os.system("iptables -F")
        sys.exit(0)
