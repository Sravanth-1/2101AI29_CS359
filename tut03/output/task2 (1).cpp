#include <iostream>
#include <pcap.h>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

bool synCaptured = false;
bool synAckCaptured = false;
bool ackCaptured = false;
bool finAckCapturedAB = false; // FIN-ACK from A to B
bool finAckCapturedBA = false; // FIN-ACK from B to A
u_char synPacket[1514];
u_char synAckPacket[1514];
u_char ackPacket[1514];

bool finAckCapturedSrcToUser = false; // FIN-ACK from source to user
bool finAckCapturedUserToSrc = false; // FIN-ACK from user to source
u_char finAckPacketSrcToUser[1514];
u_char finAckPacketUserToSrc[1514];
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
   struct ip *ipHeader = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4); // Skip IP header

    // Filter packets for the desired FIN-ACK handshake
    if (tcpHeader->fin && tcpHeader->ack) {
        if (ipHeader->ip_src.s_addr == inet_addr("10.0.2.15") && ipHeader->ip_dst.s_addr == inet_addr("164.100.160.96")) {
            // Capture FIN-ACK packet from source to user
            memcpy(finAckPacketSrcToUser, packet, pkthdr->len);
            finAckCapturedSrcToUser = true;
            std::cout << "Captured FIN-ACK packet from source to user" << std::endl;
        } else if (ipHeader->ip_src.s_addr == inet_addr("164.100.160.96") && ipHeader->ip_dst.s_addr == inet_addr("10.0.2.15")) {
            // Capture FIN-ACK packet from user to source
            memcpy(finAckPacketUserToSrc, packet, pkthdr->len);
            finAckCapturedUserToSrc = true;
            std::cout << "Captured FIN-ACK packet from user to source" << std::endl;
        }
    }

    // Check if both FIN-ACK packets have been captured
    if (finAckCapturedSrcToUser && finAckCapturedUserToSrc) {
        // Export both FIN-ACK packets to a pcap file
        pcap_t *pcapFile;
        pcap_dumper_t *pcapDumper;
        pcapFile = pcap_open_dead(DLT_EN10MB, 65535);
        pcapDumper = pcap_dump_open(pcapFile, "task2.pcap");

        // Write FIN-ACK packet from A to B
        struct pcap_pkthdr pcapHeader;
        pcapHeader.ts = pkthdr->ts;
        pcapHeader.caplen = pkthdr->len;
        pcapHeader.len = pkthdr->len;
        pcap_dump((u_char *)pcapDumper, &pcapHeader, finAckPacketUserToSrc);

        // Write FIN-ACK packet from B to A
        pcapHeader.ts = pkthdr->ts; // Copy timestamp
        pcapHeader.caplen = pkthdr->len;
        pcapHeader.len = pkthdr->len;
        pcap_dump((u_char *)pcapDumper, &pcapHeader, finAckPacketSrcToUser);
        pcap_dump_close(pcapDumper);
        pcap_close(pcapFile);

        std::cout << "Captured and exported FIN-ACK handshake. Exiting." << std::endl;
        exit(0);
    }
}

int main() {
    char *dev;
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        std::cerr << "pcap_lookupdev() failed: " << errbuf << std::endl;
        return 1;
    }

    descr = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (descr == nullptr) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }
    struct bpf_program fp;
    char filter_exp[] = "tcp and host 10.0.2.15 and host 164.100.160.96"; // Replace with your source and destination IP addresses
    if (pcap_compile(descr, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile() failed: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        std::cerr << "pcap_setfilter() failed: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    pcap_loop(descr, 0, packetHandler, nullptr);
    pcap_close(descr);

    return 0;
}

