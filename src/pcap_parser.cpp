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

#include <unistd.h>
#include <signal.h>
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
#include <bits/signum.h>

#include "pcap_parser.h"

using namespace std;

// debug
u_int n = 0,
      ip_cnt = 0,
      other_cnt = 0,
      ip_tcp_cnt = 0,
      ip_udp_cnt = 0,
      ip_other_cnt = 0,
      dns_cnt = 0;

int rr_count_total = 0;

string result;
pcap_t *handle = nullptr;

string read_domain_name(u_char *dns_hdr, u_char *dns, u_int32_t *shift)
{
    string name;
    u_int32_t offset;
    bool ptr = false;
    *shift = 0;

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

            if (!ptr) {
                (*shift)++;
            }
        }

        dns++;
        name += '.';

        if (!ptr) {
            (*shift)++;
        }
    }

    name.pop_back();
    name += '\0';

    if (ptr) {
        (*shift) += 2;
    }
    else {
        (*shift)++;
    }

    return name;
}

string read_ipv4(u_char *dns_reader)
{
    in_addr address;
    memcpy(&address, dns_reader, sizeof(address));
    char ipv4[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &address, ipv4, INET_ADDRSTRLEN);
    return static_cast<string> (ipv4);
}

string read_ipv6(u_char *dns_reader)
{
    in6_addr address;
    memcpy(&address, dns_reader, sizeof(address));
    char ipv6[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &address, ipv6, INET6_ADDRSTRLEN);
    return static_cast<string> (ipv6);
}

string read_mx(u_char *dns_hdr, u_char *dns)
{
    string data;
    u_int32_t shift;
    dns_rd_mx_t *dns_rd_mx = nullptr;

    dns_rd_mx = (dns_rd_mx_t *) dns;

    data = to_string(ntohs(dns_rd_mx->preference)).append(" ");
    data.append(read_domain_name(dns_hdr, dns + sizeof(dns_rd_mx_t), &shift));

    return data;
}

string read_soa(u_char *dns_hdr, u_char *dns)
{
    string data;
    u_int32_t shift;
    dns_rd_soa_t *dns_rd_soa = nullptr;

    data = read_domain_name(dns_hdr, dns, &shift).append(" ");
    dns += shift;

    data.append(read_domain_name(dns_hdr, dns, &shift).append(" "));
    dns += shift;

    dns_rd_soa = (dns_rd_soa_t *) dns;

    data.append(to_string(ntohl(dns_rd_soa->serial)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->refresh)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->retry)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->expire)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->minimum)).append(" "));

    return data;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_hdr, const u_char *packet)
{
    (void) args; (void) packet_hdr; // Stop yelling at me!

    struct ether_header *eth     = nullptr;
    struct ip           *ip_     = nullptr;
    struct udphdr       *udp     = nullptr;
    dns_header_t          *dns_hdr = nullptr;
    dns_rr_t          *dns_ans = nullptr;
    u_char              *dns     = nullptr;

    const u_int eth_len     = 14,
                udp_len     = 8,
                dns_hdr_len = 12;

    u_int ip_len;

    u_int32_t shift;

    string name,
           data,
           type;

    n++; // debug
    eth = (ether_header *) packet;

    /* Filter just IP frames */
    switch (ntohs(eth->ether_type)) {

        case ETHERTYPE_IP:
            ip_cnt++;
            ip_ = (ip *) (packet + eth_len);
            ip_len = ip_->ip_hl * 4;
            break;

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

    dns_hdr = (dns_header_t *) ((char *) udp + udp_len);

    /* Filter just responses */
    if (!(ntohs(dns_hdr->flags) & 0b1000000000000000)) {
        cerr << "Not a response" << endl;
        return;
    }

    /* Filter just no error responses */
    if (ntohs(dns_hdr->flags) & 0b0000000000001111) {
        cerr << "There's an error in the response" << endl;
        return;
    }

    /* Filter just responses with 1 question (other makes no sense)
     * source: https://stackoverflow.com/questions/7565300/identifying-dns-packets */
    if (ntohs(dns_hdr->qd_count) != 1) {
        cerr << "There's no 1 question" << endl;
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
    dns += (1 + sizeof(dns_query_t));

    // Mozna prochazet i zbyle typy records (?)
    int rr_count = ntohs(dns_hdr->an_count) + ntohs(dns_hdr->ns_count); // + ntohs(dns_hdr->ar_count);
    rr_count_total += rr_count;

    /* For every answer */
    for (int i = 0; i < rr_count; i++) {

        fprintf(stderr, "DNS answer (%d)\n", i + 1);

        name = read_domain_name((u_char *) dns_hdr, dns, &shift);

        fprintf(stderr, "    domain_name = %s\n", name.c_str());

        dns_ans = (dns_rr_t *) (dns + shift);

        fprintf(stderr, "    type = %d\n", ntohs(dns_ans->type));
        fprintf(stderr, "    class = %d\n", ntohs(dns_ans->class_));
        fprintf(stderr, "    ttl = %d\n", ntohl(dns_ans->ttl));
        fprintf(stderr, "    data_len = %d\n", ntohs(dns_ans->data_len));

        dns += sizeof(dns_rr_t);

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
                data = read_domain_name((u_char *) dns_hdr, dns, &shift);
                type = "CNAME";
                break;

            case DNS_DS:
                data = "ToDo";
                type = "DS";
                break;

            case DNS_MX:
                data = read_mx((u_char *) dns_hdr, dns);
                type = "MX";
                break;

            case DNS_NS:
                data = read_domain_name((u_char *) dns_hdr, dns, &shift);
                type = "NS";
                break;

            case DNS_NSEC:
                // ToDo
                data = "ToDo";
                type = "NSEC";
                break;

            case DNS_PTR:
                data = read_domain_name((u_char *) dns_hdr, dns, &shift);
                type = "PTR";
                break;

            case DNS_RRSIG:
                // ToDo
                data = "ToDo";
                type = "RRSIG";
                break;

            case DNS_SOA:
                data = read_soa((u_char *) dns_hdr, dns);
                type = "SOA";
                break;

            case DNS_SPF:
                // ToDo
                data = "ToDo";
                type = "SPF";
                break;

            case DNS_TXT:
                // ToDo
                data = "ToDo";
                type = "TXT";
                break;

            default:
                // ToDo
                data = "unknown_data";
                type = "unknown_type";
                break;
        }
        dns += ntohs(dns_ans->data_len);

        fprintf(stderr, "    data = %s\n\n", data.c_str());
        fprintf(stderr, "%s %s %s\n\n", name.c_str(), type.c_str(), data.c_str());

//        if (ntohs(dns_ans->type) == DNS_MX)
            result += name.append(" ") + type.append(" ") + data.append("\n");
    }

//    if (ntohs(dns_hdr->id) == 0x5443) {
//        cout << result << endl;
//        exit(0);
//    }
}

void signal_handler(int sig)
{
    switch (sig) {
        case SIGALRM:
            pcap_breakloop(handle);
            break;
        case SIGUSR1:
            cout << result;
            break;
    }
}

PcapParser::PcapParser(std::string filename, std::string interface):
    m_filename(filename),
    m_interface(interface)
{
}

PcapParser::~PcapParser()
{
}

void PcapParser::parse_file()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = nullptr;

    signal(SIGUSR1, signal_handler);

    handle = pcap_open_offline(m_filename.c_str(), error_buffer);
    if (handle == nullptr) {
        fprintf(stderr, "Could not open device %s: %s\n", m_interface.c_str(), error_buffer);
        return;
    }
    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);

    // ToDo: send to syslog
    cout << result;

    cout << endl;
    cout << "Summary: " << endl;
    cout << "other = " << other_cnt << endl;
    cout << "IP = " << ip_cnt << endl;
    cout << "    other = " << ip_other_cnt << endl;
    cout << "    TCP = " << ip_tcp_cnt << endl;
    cout << "    UDP = " << ip_udp_cnt << endl;
    cout << "        DNS = " << dns_cnt << endl;
    cout << "            Record count in total = " << rr_count_total << endl;
}

void PcapParser::parse_interface(u_int timeout)
{
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};

    alarm(timeout);
    signal(SIGALRM, signal_handler);
    signal(SIGUSR1, signal_handler);

    /* Open device for live capture */
    handle = pcap_open_live(m_interface.c_str(), BUFSIZ, 1, 1000, error_buffer);
    if (handle == nullptr) {
        fprintf(stderr, "Could not open device %s: %s\n", m_interface.c_str(), error_buffer);
        return;
    }
    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);

    // ToDo: send to syslog
    cout << result;

    cout << endl;
    cout << "Summary: " << endl;
    cout << "other = " << other_cnt << endl;
    cout << "IP = " << ip_cnt << endl;
    cout << "    other = " << ip_other_cnt << endl;
    cout << "    TCP = " << ip_tcp_cnt << endl;
    cout << "    UDP = " << ip_udp_cnt << endl;
    cout << "        DNS = " << dns_cnt << endl;
}
