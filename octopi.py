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

log_file = None

def spoof_scan(packet):
    global flushed  
    global PORTS
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
                        if log_file is not None:
                            log_file.write("turned back on")

                        # print "turned back on"
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
            if log_file is not None:
                log_file.write("Scan:\t%d\tFrom:\t%s" % (ret_pkt["TCP"].sport, ret_pkt["IP"].dst)

            # print "Scan:\t%d\tFrom:\t%s" % (ret_pkt["TCP"].sport, ret_pkt["IP"].dst)
            send(ret_pkt, verbose=False)

        # kill switch
        elif tcp_flag == "PA":
            if not pkt.haslayer(Raw):
                packet.accept()
                return
            else:
                if pkt["TCP"].dport == TOGGLE:
                    raw_bytes = pkt["Raw"].load.decode("utf-8")
                    try:
                        if banner in raw_bytes:
                            packet.drop()
                            flushed = True
                            if log_file is not None:
                                log_file.write("turned it off")

                            # print "turned it off"
                        elif int(raw_bytes, 10):
                            PORTS.append(int(raw_bytes, 10))

                    except ValueError:
                        pass
                
                packet.accept()
                return



        else:
            packet.accept()
        

    except Exception as e:
        if log_file is not None:
            log_file.write(e)
            log_file.write("ERROR")
        # print e
        # print "ERROR"

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
        log_file = open("/tmp/shit.log", "w")
    except IOError:
        log_file = None



    try:
        os.system(NFQUEUE_TABLE)
        if log_file is not None:
            log_file.write("UPDATED IPTABLES...")
        # print "UPDATED IPTABLES..." 

        nfqueue = NetfilterQueue()
        if log_file is not None:
            log_file.write("CREATED NFQUEUE...")
        # print "CREATED NFQUEUE"
        # 1 is iptables rule queue number, filter_get_requests is callback function
        nfqueue.bind(1, spoof_scan)
        nfqueue.run()

    except KeyboardInterrupt:
        nfqueue.unbind()
        if log_file is not None:
            log_file.write("Ending Octopi...")
            log_file.close()
        # print "Ending Octopi"
        os.system("iptables -F")
        sys.exit(0)
