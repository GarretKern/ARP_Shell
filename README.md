# ARP Shell
ARP Shell uses ARP (Address Resolution Protocol) to smuggle data over layer 2.

## Design

**Sending** messages:

The sending host sends hex-encoded data in the source hardware (MAC) address field of ARP packets. The sending host spoofs the broadcast_ip, an
IP address used an indicator for the receiving host to capture packets. 6 characters are sent per ARP message.

**Receiving** messages:

The receiving host sniffs all incoming arp packets that involve the broadcast_ip. 
When a packet is received with decoded data containing a null byte, the receiving host stops sniffing,
and pieces together the data contained in the sniffed packets. 
