// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <string>
#include <iostream>

#include <sys/socket.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "pcap_parser.h"

using namespace std;

u_int n = 0,
      ip_cnt = 0,
      arp_cnt = 0,
      ipv6_cnt = 0,
      other_cnt = 0,
      ip_tcp_cnt = 0,
      ip_udp_cnt = 0,
      ip_other_cnt = 0;

struct dns_header
{
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qd_count;
    u_int16_t an_count;
    u_int16_t ns_count;
    u_int16_t ar_count;
};

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *ether_hdr = nullptr;
    struct ip *ip_hdr = nullptr;
    struct udphdr *udp_hdr = nullptr;
    void *dns_hdr = nullptr;
    dns_header *dns;

    u_int ethernet_header_length = 14; /* Doesn't change */
    u_int ip_header_length;
    u_int udp_header_length = 8; /* Doesn't change */
    u_int dns_header_length = 12; /* Doesn't change */

    n++;
    ether_hdr = (struct ether_header *) packet;

    switch (ntohs(ether_hdr->ether_type)) {

        case ETHERTYPE_IP:
            ip_cnt++;

            /* Find start of IP header */
            ip_hdr = (struct ip *) (packet + ethernet_header_length);
            ip_header_length = ip_hdr->ip_hl * 4;

            switch (ip_hdr->ip_p) {

                case IPPROTO_UDP:
                    ip_udp_cnt++;

                    printf("Packet no. %d:\n",n);
                    printf("    &packet: %u\n", packet);
                    printf("    Length %d, received at %s", header->len, ctime((const time_t*) & header->ts.tv_sec));
                    printf("    Source MAC: %s\n", ether_ntoa((const struct ether_addr *) & ether_hdr->ether_shost));
                    printf("    Destination MAC: %s\n", ether_ntoa((const struct ether_addr *) & ether_hdr->ether_dhost));
                    printf("    Ethernet type is  0x%x, i.e. IP packet \n", ntohs(ether_hdr->ether_type));
                    printf("    IP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",
                           ntohs(ip_hdr->ip_id), ip_header_length, ip_hdr->ip_v, ntohs(ip_hdr->ip_len), ip_hdr->ip_ttl);
                    printf("    IP src = %s, ", inet_ntoa(ip_hdr->ip_src));
                    printf("IP dst = %s", inet_ntoa(ip_hdr->ip_dst));

                    printf(", protocol UDP (%d)\n", ip_hdr->ip_p);

                    dns_hdr = (void *) (packet + ethernet_header_length + ip_header_length + udp_header_length);

                    printf("Ethernet header length: %d\n", ethernet_header_length);
                    printf("IP header length:       %d\n", ip_header_length);
                    printf("UDP header length:      %d\n", udp_header_length);

                    dns = (dns_header *) dns_hdr;

                    printf("DNS header:\n");
                    printf("    &dns_hdr: %d\n", dns_hdr);
                    printf("    id = 0x%04x\n", ntohs(dns->id));
                    printf("    flags = 0x%04x\n", ntohs(dns->flags));
                    printf("    qd_count = %d\n", ntohs(dns->qd_count));
                    printf("    an_count = %d\n", ntohs(dns->an_count));
                    printf("    ns_count = %d\n", ntohs(dns->ns_count));
                    printf("    ar_count = %d\n", ntohs(dns->ar_count));

                    cout << endl;

                    if (ntohs(dns->id) == 0xab47 && (dns->flags & 0b1000000000000000)) {
                        exit(0);
                    }

                    break;

                case IPPROTO_TCP:
                    ip_tcp_cnt++;
                    break;

                default:
                    ip_other_cnt++;
                    break;
            }
            break;

        case ETHERTYPE_ARP:
            arp_cnt++;
            break;

        case ETHERTYPE_IPV6:
            ipv6_cnt++;
            break;

        default:
            other_cnt++;
            break;
    }









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
    cout << "Summary: " << endl;
    cout << "IP = " << ip_cnt << endl;
    cout << "    TCP = " << ip_tcp_cnt << endl;
    cout << "    UDP = " << ip_udp_cnt << endl;
    cout << "    other = " << ip_other_cnt << endl;
    cout << "ARP = " << arp_cnt << endl;
    cout << "IPv6 = " << ipv6_cnt << endl;
    cout << "other = " << other_cnt << endl;

    // ToDo
}
