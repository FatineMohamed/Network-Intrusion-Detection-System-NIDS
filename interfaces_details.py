from scapy.all import IFACES

for iface in IFACES.values():
    print("=" * 50)
    print("Name:", iface.name)
    print("Description:", iface.description)