from scapy.all import get_if_list

for interface in get_if_list():
    print(interface)