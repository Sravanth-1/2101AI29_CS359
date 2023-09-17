#include <iostream>
#include <pcap.h>
#include <cstring>
#include <netinet/ip.h> // Include this for 'struct ip'
#include <arpa/inet.h>  // Include this for inet_ntoa

struct EthernetHeader {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
};

bool isFirstPacket = true;
u_char firstPacket[1514]; // Adjust the size as needed
char srcIpA[16];          // Store the source IP of A
char dstIpB[16];          // Store the destination IP of B

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ipHeader = (struct ip *)(packet + 14); // Skip Ethernet header

    if (isFirstPacket) {
        memcpy(firstPacket, packet, pkthdr->len);
        strcpy(srcIpA, inet_ntoa(ipHeader->ip_src));
        strcpy(dstIpB, inet_ntoa(ipHeader->ip_dst));
        isFirstPacket = false;
    } else {
        char srcIp[16];
        char dstIp[16];
        strcpy(srcIp, inet_ntoa(ipHeader->ip_src));
        strcpy(dstIp, inet_ntoa(ipHeader->ip_dst));

        if (strcmp(srcIp, dstIpB) == 0 && strcmp(dstIp, srcIpA) == 0) {
            // The second packet matches the criteria, export both packets
            pcap_t *pcapFile;
            pcap_dumper_t *pcapDumper;
            pcapFile = pcap_open_dead(DLT_EN10MB, 65535);
            pcapDumper = pcap_dump_open(pcapFile, "udp.pcap");

            // Write the first packet
            struct pcap_pkthdr pcapHeader;
            pcapHeader.ts = pkthdr->ts;
            pcapHeader.caplen = pkthdr->len;
            pcapHeader.len = pkthdr->len;
            pcap_dump((u_char *)pcapDumper, &pcapHeader, firstPacket);

            // Write the second packet
            pcapHeader.ts = pkthdr->ts; // Copy timestamp
            pcapHeader.caplen = pkthdr->len;
            pcapHeader.len = pkthdr->len;
            pcap_dump((u_char *)pcapDumper, &pcapHeader, packet);

            pcap_dump_close(pcapDumper);
            pcap_close(pcapFile);

            std::cout << "Exiting." << std::endl;
            exit(0);
        }
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
    char filter_exp[] = "udp"; // Modify the filter to capture UDP packets
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

