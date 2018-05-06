#!/usr/bin/python

from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import sys
import os

banner = "EASTER BUNNY'S FLUFFY WHITE COCK"
start_up_banner = "CAESAR SALAD COCK"
flushed = False
TOGGLE = 6969
NFQUEUE_TABLE = "iptables -A INPUT -j NFQUEUE --queue-num 1"
PORTS = []

def spoof_scan(packet):
    global flushed  
    try:
        pkt = IP(packet.get_payload())
        if flushed:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp_flag = pkt.sprintf("%TCP.flags%")
                if pkt["TCP"].dport == TOGGLE and tcp_flag == "PA":
                    raw_bytes = pkt["Raw"].load.decode("utf-8")
                    if start_up_banner in raw_bytes:
                        flushed = False
                        os.system(NFQUEUE_TABLE)
                        print "turned back on"
                        packet.drop()
                        return

            # by default just accept all packets if not the toggle packet
            packet.accept()
            return


        # if it's not a TCP packet, let it through
        if not pkt.haslayer(TCP):
            packet.accept()
            return

        # if it's not a SYN packet
        tcp_flag = pkt.sprintf("%TCP.flags%")
        if tcp_flag == "S":
            # uncomment to set specific ports to allow through
            if pkt["TCP"].dport in PORTS:
                packet.accept()
                return
            # spoof the fake reply
            ret_pkt = IP(src=pkt["IP"].dst, dst=pkt["IP"].src, ttl=pkt["IP"].ttl - 1)/ \
                    TCP(dport=pkt["TCP"].sport, sport=pkt["TCP"].dport, seq=1234, ack=pkt["TCP"].seq + 1, flags="SA")

            packet.drop()
            print "Scan:\t%d\tFrom:\t%s" % (ret_pkt["TCP"].sport, ret_pkt["IP"].dst)
            send(ret_pkt, verbose=False)

        # kill switch
        elif tcp_flag == "PA":
            if not pkt.haslayer(Raw):
                packet.accept()
                return
            else:
                if pkt["TCP"].dport == TOGGLE:
                    raw_bytes = pkt["Raw"].load.decode("utf-8")
                    if banner in raw_bytes:
                        packet.drop()
                        flushed = True
                        print "turned it off"


        else:
            packet.accept()
        

    except Exception as e:
        print e
        print "ERROR"

if __name__ == "__main__":
    global nfqueue
    parser = argparse.ArgumentParser()
    parser.add_argument("--rangeL", type=int)
    parser.add_argument("--rangeH", type=int)
    parser.add_argument("--ports", type=int, nargs="+")

    args = parser.parse_args()

    # add special exception for specialty ports
    ports_to_add = args.ports
    if ports_to_add is not None:
        for p in ports_to_add:
            PORTS.append(p)

    low = args.rangeL
    high = args.rangeH
    if (low is not None) and (high is not None):
        for p in range(low, high + 1):
            PORTS.append(p)


    try:
        os.system(NFQUEUE_TABLE)
        print "UPDATED IPTABLES..."

        nfqueue = NetfilterQueue()
        print "CREATED NFQUEUE..."
        # 1 is iptables rule queue number, filter_get_requests is callback function
        nfqueue.bind(1, spoof_scan)
        nfqueue.run()

    except KeyboardInterrupt:
        nfqueue.unbind()
        print "Ending Octopi"
        os.system("iptables -F")
        sys.exit(0)
