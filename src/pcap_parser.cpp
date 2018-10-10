// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <string>
#include <iostream>
#include <bitset>
#include <vector>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/udp.h>

#include "pcap_parser.h"

using namespace std;

// debug
u_int n = 0,
      ip_cnt = 0,
      arp_cnt = 0,
      ipv6_cnt = 0,
      other_cnt = 0,
      ip_tcp_cnt = 0,
      ip_udp_cnt = 0,
      ip_other_cnt = 0,
      dns_cnt = 0;

/*
 * struct in6_addr {
 *     unsigned char   s6_addr[16];   // IPv6 address
 * };
 *
 * INET6_ADDRSTRLEN = 46;
 *
 * // Convert IPv4 and IPv6 addresses from binary to text form
 * const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
 */
string read_ipv6(u_char *dns_reader)
{
    in6_addr address;
    memcpy(&address, dns_reader, sizeof(address));
    char ipv6[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &address, ipv6, INET6_ADDRSTRLEN);
    return static_cast<string> (ipv6);
}

/*
 * struct in_addr {
 *     unsigned long s_addr;  // load with inet_aton()
 * };
 * INET6_ADDRSTRLEN = 16;
 */
string read_ipv4(u_char *dns_reader)
{
    in_addr address;
    memcpy(&address, dns_reader, sizeof(address));
    char ipv4[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &address, ipv4, INET_ADDRSTRLEN);
    return static_cast<string> (ipv4);
}

string read_name(u_char *dns_hdr, u_char *dns, u_int32_t *shift)
{
    string name;
    u_int32_t offset;
    bool ptr = false;

    while (*dns != '\0') {
        /* "The significance of the compression label is as follows: the first 2 bits are set to 1,
         * the 14 remaining bits describe the offset, i.e. the position of the compression target
         * from the beginning of the DNS message." */
        if (*dns >= 0b11000000) {
            offset = (u_int32_t) ((*dns) * 0x100 + *(dns + 1) - 0xC000); // calculation of offset
            dns = dns_hdr + offset;
            ptr = true;
        }

        for (int cnt = *dns; cnt > 0; cnt--) {
            dns++;
            name += *dns;
        }
        name += '.';
        dns++;
    }

    name.pop_back();
    name += '\0';

    /* If't was pointer, shift just 2 bytes */
    if (ptr) {
        *shift = 2;
    }
    /* If't was a whole dns name, shift length of the string + 1 */
    else {
        *shift = (u_int32_t) name.length() + 1;
    }

    return name;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_hdr, const u_char *packet)
{
    (void) args; (void) packet_hdr; // Stop yelling at me!

    struct ether_header *eth     = nullptr;
    struct ip           *ip_     = nullptr;
    struct udphdr       *udp     = nullptr;
    DnsHeader          *dns_hdr = nullptr;
    DnsAnswer          *dns_ans = nullptr;
    u_char              *dns     = nullptr;

    const u_int eth_len     = 14,
                udp_len     = 8,
                dns_hdr_len = 12;

    u_int ip_len,
          shift;

    string name,
           data,
           type,
           result;


    n++; // debug
    eth = (ether_header *) packet;

    /* Filter just IP frames */
    switch (ntohs(eth->ether_type)) {

        case ETHERTYPE_IP:
            ip_cnt++;
            ip_ = (ip *) (packet + eth_len);
            ip_len = ip_->ip_hl * 4;
            break;

        case ETHERTYPE_ARP:
            arp_cnt++;
            return;

        case ETHERTYPE_IPV6:
            ipv6_cnt++;
            return;

        default:
            other_cnt++;
            return;
    }

    /* Filter just UDP communication */
    switch (ip_->ip_p) {

        case IPPROTO_UDP:
            ip_udp_cnt++;
            udp = (udphdr *) ((char *) ip_ + ip_len);
            break;

        case IPPROTO_TCP:
            ip_tcp_cnt++;
            return;

        default:
            ip_other_cnt++;
            return;
    }

    /* Filter just communication with source port 53 */
    if (ntohs(udp->source) != 53) {
        cerr << "Not source port 53" << endl;
        return;
    }

    dns_hdr = (DnsHeader *) ((char *) udp + udp_len);

    /* Filter just responses */
    if (!(ntohs(dns_hdr->flags) & 0b1000000000000000)) {
        cerr << "Not a response" << endl;
        return;
    }

    /* Filter just no error responses */
    if (ntohs(dns_hdr->flags) & 0b0000000000001111)  {
        cerr << "There's an error in the response" << endl;
        return;
    }

    /* Filter just responses with 1 question (other makes no sense)
     * source: https://stackoverflow.com/questions/7565300/identifying-dns-packets */
    if (ntohs(dns_hdr->qd_count) != 1) {
        cerr << "There's no 1 question" << endl;
        return;
    }

    /* Filter just responses with answers */
    if (ntohs(dns_hdr->an_count) == 0) {
        cerr << "There's no answer" << endl;
        return;
    }

    dns_cnt++; // DNS traffic

    fprintf(stderr, "------------------------------------------------------------------------------\n\n");
    fprintf(stderr, "Packet no. %d\n", n);
    fprintf(stderr, "    Length: %d\n", packet_hdr->len);
    fprintf(stderr, "    Source MAC: %s\n", ether_ntoa((const struct ether_addr *) & eth->ether_shost));
    fprintf(stderr, "    Destination MAC: %s\n", ether_ntoa((const struct ether_addr *) & eth->ether_dhost));
    fprintf(stderr, "    Ethernet type: 0x%x (IP packet)\n", ntohs(eth->ether_type));
    fprintf(stderr, "    IP: hlen %d bytes, version %d, total length %d bytes, TTL %d\n", ip_len,
            ip_->ip_v, ntohs(ip_->ip_len), ip_->ip_ttl);
    fprintf(stderr, "    IP src = %s, ", inet_ntoa(ip_->ip_src));
    fprintf(stderr, "IP dst = %s", inet_ntoa(ip_->ip_dst));
    fprintf(stderr, ", protocol UDP (%d)\n\n", ip_->ip_p);

    fprintf(stderr, "DNS header\n");
    fprintf(stderr, "    id = 0x%04x\n", ntohs(dns_hdr->id));
    fprintf(stderr, "    flags = 0x%04x\n", ntohs(dns_hdr->flags));
    fprintf(stderr, "    qd_count = %d\n", ntohs(dns_hdr->qd_count));
    fprintf(stderr, "    an_count = %d\n", ntohs(dns_hdr->an_count));
    fprintf(stderr, "    ns_count = %d\n", ntohs(dns_hdr->ns_count));
    fprintf(stderr, "    ar_count = %d\n\n", ntohs(dns_hdr->ar_count));

    dns = (u_char *) dns_hdr + dns_hdr_len;

    /* Skip query (name + 2 + 2) */
    while (*(++dns) != '\0')
        ;
    dns += (1 + sizeof(DnsQuery));

    /* For every answer */
    for (int i = 0; i < ntohs(dns_hdr->an_count); i++) {

        fprintf(stderr, "DNS answer (%d)\n", i + 1);

        name = read_name((u_char *) dns_hdr, dns, &shift);

        fprintf(stderr, "    domain_name = %s\n", name.c_str());

        dns_ans = (DnsAnswer *) (dns + shift);

        fprintf(stderr, "    type = %d\n", ntohs(dns_ans->type));
        fprintf(stderr, "    class = %d\n", ntohs(dns_ans->class_));
        fprintf(stderr, "    ttl = %d\n", ntohl(dns_ans->ttl));
        fprintf(stderr, "    data_len = %d\n", ntohs(dns_ans->data_len));

        dns = dns + sizeof(DnsAnswer);

        switch (ntohs(dns_ans->type)) {

            case DNS_A:
                data = read_ipv4(dns);
                type = "A";
                break;

            case DNS_AAAA:
                data = read_ipv6(dns);
                type = "AAAA";
                break;

            case DNS_CNAME:
                // Shift is not gonna be used
                data = read_name((u_char *) dns_hdr, dns, &shift);
                type = "CNAME";
                break;

            case DNS_DS:
                break;

            case DNS_MX:
                break;

            case DNS_NS:
                break;

            case DNS_NSEC:
                break;

            case DNS_PTR:
                break;

            case DNS_RRSIG:
                break;

            case DNS_SOA:
                break;

            case DNS_SPF:
                break;

            case DNS_TXT:
                break;

            default:
                break;
        }
        dns += ntohs(dns_ans->data_len);

        fprintf(stderr, "    data = %s\n\n", data.c_str());
        fprintf(stderr, "%s %s %s\n\n", name.c_str(), type.c_str(), data.c_str());

        result += name.append(" ") + type.append(" ") + data.append("\n");
    }

    cout << result;

//    if (ntohs(dns_hdr->id) == 0xa2bc) {
//        exit(0);
//    }
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
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *handle = nullptr;
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    handle = pcap_open_offline(m_filename.c_str(), error_buffer);
    packet = pcap_next(handle, &packet_header);

    if (packet == NULL) {
        cerr << "No packet found." << endl;
        return;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);

    cout << endl;
    cout << "Summary: " << endl;
    cout << "ARP = " << arp_cnt << endl;
    cout << "IPv6 = " << ipv6_cnt << endl;
    cout << "other = " << other_cnt << endl;
    cout << "IP = " << ip_cnt << endl;
    cout << "    other = " << ip_other_cnt << endl;
    cout << "    TCP = " << ip_tcp_cnt << endl;
    cout << "    UDP = " << ip_udp_cnt << endl;
    cout << "        DNS = " << dns_cnt << endl;

    // ToDo
}
