from scapy.all import *
import socket

def capture_close():
    a=sniff(count=10,lfilter=lambda x:x.haslayer(TCP) and x[TCP].flags==17)
    for item in a:
            packet=[]
            packet.append(item)
            port_src=item[TCP].sport
            port_dst=item[TCP].dport
            for item2 in a:
                if item2[TCP].sport==port_dst and item2[TCP].dport==port_src:
                    packet.append(item2)
                    wrpcap("TCP_handshake_close.pcap",packet)
                    return
    capture_close()

def capture_2_tcp():
    a=sniff(count=10,lfilter=lambda x:x.haslayer(TCP) and x[TCP].flags==16)
    for item in a:
            packet=[]
            packet.append(item)
            port_src=item[TCP].sport
            port_dst=item[TCP].dport
            for item2 in a:
                if item2[TCP].sport==port_dst and item2[TCP].dport==port_src:
                    packet.append(item2)
                    wrpcap("TCP_Packets.pcap",packet)
                    return
    capture_2_tcp()

def capture_2_udp():
    a=sniff(count=10,lfilter=lambda x:x.haslayer(UDP))
    for item in a:
            packet=[]
            packet.append(item)
            port_src=item[UDP].sport
            port_dst=item[UDP].dport
            for item2 in a:
                if item2[UDP].sport==port_dst and item2[UDP].dport==port_src:
                    packet.append(item2)
                    wrpcap("UDP_Packets.pcap",packet)
                    return
    capture_2_udp()
    

target_website = "www.nic.in"
target_port = 80

target_ip = socket.gethostbyname(target_website)

packet = []
ip = IP(dst=target_ip)
tcp = TCP(dport=target_port, flags="S", seq=1000)
syn_packet = ip / tcp
print("SYN Packet:")
print(syn_packet.summary())
packet.append(syn_packet)
syn_response = sr1(syn_packet, timeout=5)  # Send SYN packet and wait for response

if syn_response is None:
    print("No response to SYN packet. The host may be unreachable or the port may be closed.")
else:
    print("\nReceived SYN-ACK packet from the server:")
    print(syn_response.summary())
    packet.append(syn_response)
    print("Server's IP address:", syn_response.src)
    print("Server's Port:", syn_response.sport)

    # Step 2: Send ACK packet
    ack_packet = ip / TCP(dport=target_port, sport=syn_response.dport, flags="A", seq=syn_response.ack, ack=syn_response.seq + 1)
    print("\nACK Packet:")
    print(ack_packet.summary())
    packet.append(ack_packet)
    wrpcap("t1.pcap", packet)
    send(ack_packet)
    print("Sent ACK packet to establish the connection.")

capture_close()
capture_2_tcp()
capture_2_udp()