#include <iostream>
#include <pcap.h>
#include <cstring>

// Ethernet header struct
struct EthernetHeader {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
};

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int packetCount = 0;
    static u_char packet1[1514]; // Adjust the size as needed
    static u_char packet2[1514]; // Adjust the size as needed

    if (packetCount == 0) {
        std::cout << "Captured." << std::endl;
        memcpy(packet1, packet, pkthdr->len);
        packetCount++;
    } else if (packetCount == 1) {
        std::cout << "Captured." << std::endl;
        memcpy(packet2, packet, pkthdr->len);

        // Export both packets to a pcap file
        pcap_t *pcapFile;
        pcap_dumper_t *pcapDumper;
        pcapFile = pcap_open_dead(DLT_EN10MB, 65535);
        pcapDumper = pcap_dump_open(pcapFile, "tcp.pcap");

        // Write the 1st packet
        struct pcap_pkthdr pcapHeader;
        pcapHeader.ts = pkthdr->ts;
        pcapHeader.caplen = pkthdr->len;
        pcapHeader.len = pkthdr->len;
        pcap_dump((u_char *)pcapDumper, &pcapHeader, packet1);

        // Write the 2nd packet
        pcapHeader.ts = pkthdr->ts; // Copy timestamp
        pcapHeader.caplen = pkthdr->len;
        pcapHeader.len = pkthdr->len;
        pcap_dump((u_char *)pcapDumper, &pcapHeader, packet2);

        pcap_dump_close(pcapDumper);
        pcap_close(pcapFile);

        packetCount++;
    }
}

int main() {
    char *dev;
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find a capture device
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        std::cerr << "pcap_lookupdev() failed: " << errbuf << std::endl;
        return 1;
    }

    // Open the capture device
    descr = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (descr == nullptr) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    // Compile a BPF filter to capture TCP packets
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(descr, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile() failed: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    // Set the filter
    if (pcap_setfilter(descr, &fp) == -1) {
        std::cerr << "pcap_setfilter() failed: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    // Start capturing packets
    pcap_loop(descr, 0, packetHandler, nullptr);

    // Close the capture device (this will not be reached in this example)
    pcap_close(descr);

    return 0;
}

