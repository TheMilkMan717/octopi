#!/usr/bin/python

from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import sys
import os
import logging

banner = "EASTER BUNNY'S FLUFFY WHITE COCK"
start_up_banner = "CAESAR SALAD COCK"
flushed = False
TOGGLE = 6969
NFQUEUE_TABLE = "iptables -A INPUT -j NFQUEUE --queue-num 1"
PORTS = []

VERBOSE = False
log_file = None

def vprint(msg):
    if VERBOSE:
        print msg
    

def spoof_scan(packet):
    global flushed  
    global PORTS
    # TODO: replace hasLayer() with pktType in pkt
    # TODO: rework the logging for UDP scans for user to know the type of scan being done
    # TODO: Whitelist scans by IP address so that UDP scanning is not confused with valid DNS servers
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
                        if not (log_file is None):
                            logging.info("Octopi turned back on")
                            # log_file.write("turned back on\n")

                        print "Octopi turned back on"
                        packet.drop()
                        return

            # by default just accept all packets if not the toggle packet
            packet.accept()
            return


        if UDP in pkt:
            if pkt["UDP"].dport in PORTS:
                packet.accept()
                return
            # used for weird UDP traffic from localhost
            elif pkt["IP"].src == "127.0.0.1":
                packet.accept()
                return
            else:
                logging.info("Scan: %d\tFrom: %s" % (pkt["UDP"].dport, pkt["IP"].src))
                vprint("Scan: %d\tFrom: %s" % (pkt["UDP"].dport, pkt["IP"].src))
                packet.drop()
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
            if not (log_file is None):
                # log_file.write("Scan:\t%d\tFrom:\t%s\n" % (ret_pkt["TCP"].sport, ret_pkt["IP"].dst))
                logging.info("Scan: %d\tFrom: %s" % (ret_pkt["TCP"].sport, ret_pkt["IP"].dst))

            vprint("Scan: %d\tFrom: %s" % (ret_pkt["TCP"].sport, ret_pkt["IP"].dst))
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
                            flushed = True
                            if not (log_file is None):
                                # log_file.write("turned it off\n")
                                logging.info("Octopi has suspended")
                            packet.drop()
                            return

                            print "Octopi has suspended"
                        elif int(raw_bytes, 10):
                            PORTS.append(int(raw_bytes, 10))

                    except ValueError:
                        pass
                
                packet.accept()
                return



        else:
            packet.accept()
        

    except Exception as e:
        if not (log_file is None):
            # log_file.write(e)
            logging.warning(e)
            # log_file.write("ERROR\n")
        vprint(e)

if __name__ == "__main__":
    global nfqueue
    # global VERBOSE

    parser = argparse.ArgumentParser()
    parser.add_argument("--rangeL", type=int)
    parser.add_argument("--rangeH", type=int)
    parser.add_argument("--ports", type=int, nargs="+")
    parser.add_argument("-v", default=False, action="store_true", help="verbose mode")
    parser.add_argument("--log", type=str, default="/tmp/octopi.log", help="specify a log file, default is /tmp/octopi.log")

    args = parser.parse_args()

    # add special exception for specialty ports
    ports_to_add = args.ports
    if ports_to_add is not None:
        for p in ports_to_add:
            PORTS.append(p)

    # add a range of ports to allow through
    low = args.rangeL
    high = args.rangeH
    if (low is not None) and (high is not None):
        for p in range(low, high + 1):
            PORTS.append(p)

    # turn on verbose mode
    if args.v:
        print "Running in Verbose mode\n"
        VERBOSE = True

    LOG_FILE_NAME = args.log

    try:
        logging.basicConfig(level=logging.DEBUG,\
                            format="%(asctime)s %(levelname)-8s %(message)s",\
                            datefmt="%a, %d %b %Y %H:%M:%S",\
                            filename=LOG_FILE_NAME,\
                            filemode="w")

        # log_file = open(LOG_FILE_NAME, "w")
        log_file = "filename"
    except IOError:
        log_file = None



    try:
        os.system(NFQUEUE_TABLE)

        if not (log_file is None):
            # log_file.write("UPDATED IPTABLES...\n")
            logging.info("UPDATED IPTABLES...")

        print "UPDATED IPTABLES..." 

        nfqueue = NetfilterQueue()
        if not (log_file is None):
            # log_file.write("CREATED NFQUEUE...\n")
            logging.info("CREATED NFQUEUE...")
        print "CREATED NFQUEUE"
        # 1 is iptables rule queue number, filter_get_requests is callback function
        nfqueue.bind(1, spoof_scan)
        print "Beginning Octopi"
        vprint("\nLogging to %s" % LOG_FILE_NAME)
        nfqueue.run()

    except KeyboardInterrupt:
        nfqueue.unbind()
        if not (log_file is None):
            # log_file.write("Ending Octopi...\n")
            logging.info("Ending Octopi...")
            logging.shutdown()
            # log_file.close()
        print "Ending Octopi"
        os.system("iptables -F")
        sys.exit(0)
