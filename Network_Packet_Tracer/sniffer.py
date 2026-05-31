#We have installed scapy using pip install scapy (make sure the pip installation matches the python version you are using, e.g., pip3 for Python 3).

#Then we have import the necesary modules from scapy and datetime to get the current time when the packet is caught 

#Import specific modules from the scapy library

#sniff captures live packets on the wire

#IP allows you to examine the Internet Protocol layer

#TCP allows you to examine the Transmission Control Protocol layer

#UDP allows you to examine the User Datagram Protocol layer

#ICMP allows you to examine ping/diagnostic packets

#Raw allows you to examine the raw data payload of a packet


from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


#Function is defined to be called for each captured packet.
def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S") #Get the current time and format it as HH:MM:SS

    if IP in packet:                    #Check if the packet has an IP layer (i.e., it's an IP packet)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:                  #Check if the packet has a TCP layer (i.e., it's a TCP packet)
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[{timestamp}] TCP | {src_ip}:{src_port} → {dst_ip}:{dst_port} | Flags: {flags}")

        elif UDP in packet:                  #Check if the packet has a UDP layer (i.e., it's a UDP packet) 
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{timestamp}] UDP | {src_ip}:{src_port} → {dst_ip}:{dst_port}")

        elif ICMP in packet:                #Check if the packet has an ICMP layer (i.e., it's an ICMP packet)  
            print(f"[{timestamp}] ICMP | {src_ip} → {dst_ip} | Type: {packet[ICMP].type}")

        else:                                #If the packet is IP but not TCP, UDP, or ICMP, we can print basic info about it
            print(f"[{timestamp}] OTHER (proto {protocol}) | {src_ip} → {dst_ip}")

        
        #If the packet contains a Raw layer, we can attempt to decode and print the payload. We limit the output to 80 characters for readability.
        if Raw in packet:           
            payload = packet[Raw].load
            try:
                decoded = payload.decode('utf-8', errors='replace')[:80] 
                print(f"           Payload: {decoded}")                     # we have a huge space to print the payload but we limit it to 80 characters for readability
            except Exception as e:
                print(f"           Payload (hex): {payload.hex()[:80]}")    #If decoding fails, we can print the raw payload in hexadecimal format (also limited to 80 characters)

        print("-" * 60) #Print a separator line after each packet for better readability

#This function starts the packet sniffer with optional parameters for interface, packet count, and BPF filter.
#The sniff function from scapy is used to capture packets based on the specified parameters. 
#The packet_callback function is called for each captured packet to process and display its information.

def start_sniffer(interface=None, packet_count=0, bpf_filter=""):  
    print(f"[*] Starting packet sniffer...")
    print(f"[*] Interface : {interface or 'default'}")
    print(f"[*] Filter    : {bpf_filter or 'none'}")
    print(f"[*] Count     : {packet_count or 'unlimited'}")
    print("=" * 60)

    sniff(
        iface=interface,
        prn=packet_callback,
        count=packet_count,
        filter=bpf_filter,
        store=False
    )

if __name__  == "__main__":
    start_sniffer(packet_count=20) 
    #Start the sniffer with a limit of 20 packets for testing purposes. You can adjust this as needed or set it to 0 for unlimited capture.

#To run this script, save it as sniffer.py and execute it with appropriate permissions (e.g., sudo python sniffer.py on Linux).

# so the output will show the timestamp, protocol type, source and destination IP addresses and ports, and any payload data for each captured packet.

#Kindly look at the terminal output to see the captured packets in real-time. You can stop the sniffer by pressing Ctrl+C.