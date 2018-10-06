// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <string>
#include <iostream>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include "pcap_parser.h"

using namespace std;

int ip_cnt = 0,
        arp_cnt = 0,
        revarp_cnt = 0,
        other_cnt = 0,
        tcp_cnt = 0,
        udp_cnt = 0;

struct dns_header
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    struct ether_header *ether_hdr = (struct ether_header *) packet_body;
    const u_char *ip_hdr = nullptr;
    struct dns_header *dns_hdr = nullptr;
    u_char protocol;

    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int udp_header_length = 8; /* Doesn't change */
    int dns_header_length = 12; /* Doesn't change */

    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
        ip_cnt++;
    }
    else  if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
        arp_cnt++;
        return;
    }
    else  if (ntohs(ether_hdr->ether_type) == ETHERTYPE_REVARP) {
        revarp_cnt++;
        return;
    }
    else {
        other_cnt++;
        return;
    }

    /* Find start of IP header */
    ip_hdr = packet_body + ethernet_header_length;

    /* The second-half of the first byte in ip_hdr contains
     * the IP header length (IHL). */
    ip_header_length = ((*ip_hdr) & 0x0F);

    /* The IHL is number of 32-bit segments. Multiply by four
     * to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;

    /* Now that we know where the IP header is, we can inspect
     * the IP header for a protocol number to make sure it is
     * TCP before going any further. Protocol is always the 10th
     * byte of the IP header */
    protocol = *(ip_hdr + 9);

    if (protocol == IPPROTO_TCP) {
        tcp_cnt++;
        return;
    }
    else if (protocol == IPPROTO_UDP) {
        udp_cnt++;
    }
    else {
        return;
    }

    printf("&packet_header = %d , %p\n", packet_header, packet_header);
    printf("&packet_body = %d , %p\n", packet_body, packet_body);

    printf("IP -> UDP packet found!\n");
    printf("Packet capture length: %d\n", packet_header->caplen);
    printf("Packet total length %d\n", packet_header->len);
    printf("Ethernet header length: %d\n", ethernet_header_length);
    printf("IP header length: %d\n", ip_header_length);
    printf("UDP header length: %d\n", udp_header_length);

    dns_hdr = (dns_header *) packet_body + ethernet_header_length + ip_header_length + udp_header_length;
    printf("&dns_hdr = %d , %p\n", dns_hdr, dns_hdr);
//    printf("&packet_body - &dns_hdr = %d\n", static_cast<void *> (packet_body) - static_cast<void *> (dns_hdr));


    cout << "DNS header:" << endl;
    cout << "    id = " << dns_hdr->id << endl;
    cout << "    qr = " << dns_hdr->qr << endl;
    cout << "    rcode = " << dns_hdr->rcode << endl;
    cout << "    qdcount = " << dns_hdr->q_count << endl;
    cout << "    ans_count = " << dns_hdr->ans_count << endl;
    cout << "    auth_count = " << dns_hdr->auth_count << endl;
    cout << "    add_count = " << dns_hdr->add_count << endl;

    cout << endl;
}

PcapParser::PcapParser(std::string filename):
    m_filename(filename)
{
}

PcapParser::~PcapParser()
{
}

void PcapParser::parse()
{
    cout << "parsuju " << m_filename << endl;
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *handle = nullptr;
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    handle = pcap_open_offline(m_filename.c_str(), error_buffer);
    packet = pcap_next(handle, &packet_header);

    if (packet == NULL) {
        printf("No packet found.\n");
        return;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);

    cout << endl;
    cout << "Summary:" << endl;
    cout << "IP:     " << ip_cnt << endl;
    cout << "    - TCP = " << tcp_cnt << endl;
    cout << "    - UDP = " << udp_cnt << endl;
    cout << "ARP:    " << arp_cnt << endl;
    cout << "REVARP: " << revarp_cnt << endl;
    cout << "OTHER:  " << other_cnt << endl;

    // ToDo
}
