// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <utility>
#include "pcap_parser.h"
#include "dns_parser.h"
#include "utils.h"

using namespace std;

// Debug counters
u_int frame_cnt = 0,
      udp_cnt = 0,
      tcp_cnt = 0,
      not_udp_tcp_cnt = 0,
      ipv4_cnt = 0,
      ipv6_cnt = 0,
      not_ipv4_ipv6_cnt = 0;

// Handle of pcap resource is global because of signal handler
pcap_t *handle = nullptr;

// Global instance of DnsParser because of static methods
DnsParser dns_parser;

// Global constants just for this module
const int SNAPLEN = 1;
const int PROMISC = 1000;
const u_int ETH_HDR_LEN = 14;
const u_int IPV6_HDR_LEN = 40;
const u_int UDP_HDR_LEN = 8;

vector<pair <u_char *, u_int>> PcapParser::m_tcp_buffer;

PcapParser::PcapParser(string filter_exp):
    m_filter_exp(filter_exp),
    m_compiled_filter(),
    m_resource(""),
    m_interface("")
{
}

PcapParser::~PcapParser()
{
    pcap_close(handle);
}

void PcapParser::parse_tcp()
{
    vector<u_char *> dns_vector;
    u_char *dns = nullptr;

    u_int seq,
          payload,
          payload_2,
          tcp_hdr_len,
          dns_len;

    tcphdr *tcp_1 = nullptr,
           *tcp_2 = nullptr;

    bool *seen = static_cast<bool *>(calloc(m_tcp_buffer.size(), sizeof(bool)));

    for (u_int i = 0; i < m_tcp_buffer.size(); i++) {
        if (seen[i]) {
            continue;
        }

        tcp_1 = reinterpret_cast<tcphdr *>(m_tcp_buffer[i].first);

        seq = ntohl(tcp_1->seq);
        tcp_hdr_len = tcp_1->doff * 4U;
        payload = m_tcp_buffer[i].second - tcp_hdr_len;
        dns_len = ntohs(*reinterpret_cast<u_int16_t *>(m_tcp_buffer[i].first + tcp_hdr_len));
        dns = reinterpret_cast<u_char *>(malloc(payload));
        memcpy(dns, reinterpret_cast<u_char *>(tcp_1) + tcp_hdr_len, payload);

        DEBUG_PRINT("\n------------------------------------------------------------------------------\n\n");
        DEBUG_PRINT("Parsing TCP segment\n");
        DEBUG_PRINT("    seq_num = " + to_string(seq) + "\n");
        DEBUG_PRINT("    payload = " + to_string(payload) + "\n");
        DEBUG_PRINT("    DNS length (src) = " + to_string(dns_len) + "\n");
        DEBUG_PRINT("    DNS length (dst) = " + to_string(ntohs(*reinterpret_cast<u_int16_t *>(dns))) + "\n\n");

        seq += payload;
        dns_len -= payload;

        for (u_int j = i; j < m_tcp_buffer.size(); j++) {
            if (seen[j]) {
                continue;
            }
            if (dns_len <= 0) {
                break;
            }

            tcp_2 = reinterpret_cast<tcphdr *>(m_tcp_buffer[j].first);
            tcp_hdr_len = tcp_2->doff * 4U;
            payload_2 = m_tcp_buffer[j].second - tcp_hdr_len;

            DEBUG_PRINT("    Searching for TCP with seq_num = " + to_string(seq) + "\n");

            if (ntohl(tcp_2->seq) == seq) {
                dns = reinterpret_cast<u_char *>(realloc(dns, payload + payload_2));
                memcpy(dns + payload, reinterpret_cast<u_char *>(tcp_2) + tcp_hdr_len, payload_2);
                dns_len -= payload_2;
                seq += payload_2;
                payload += payload_2;
                seen[j] = true;

                DEBUG_PRINT("        FOUND!\n");
                DEBUG_PRINT("        payload = " + to_string(payload_2) + "\n");
                DEBUG_PRINT("        new seq_num = " + to_string(seq) + "\n");
            }
            else {
                DEBUG_PRINT("        NOT FOUND, seq = " + to_string(ntohl(tcp_2->seq)) + "\n");
            }
        }
        dns_vector.push_back(dns);
        seen[i] = true;
    }
    DEBUG_PRINT("\n------------------------------------------------------------------------------\n\n");

    for (auto &elem: dns_vector) {
        dns_parser.parse(elem + sizeof(u_int16_t));
        free(elem);
    }
    free(seen);
}

void PcapParser::udp_handle(u_char *packet, u_int offset)
{
    udp_cnt++; // debug
    auto *udp = reinterpret_cast<udphdr *>(packet + offset);

    DEBUG_PRINT("UDP header\n");
    DEBUG_PRINT("    destination port = " + to_string(ntohs(udp->dest)) + "\n");
    DEBUG_PRINT("    source port = " + to_string(ntohs(udp->source)) + "\n");

    dns_parser.parse(reinterpret_cast<u_char *>(udp) + UDP_HDR_LEN);
}

void PcapParser::tcp_handle(u_char *packet, u_int offset)
{
    tcp_cnt++; // debug
    u_int dns_size;
    auto *tcp = reinterpret_cast<tcphdr *>(packet + offset);

    // Calculate size of tcp segment
    auto *eth = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        auto ipv4 = reinterpret_cast<ip *>(packet + ETH_HDR_LEN);
        dns_size = ntohs(ipv4->ip_len) - ipv4->ip_hl * 4;
    }
    else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) {
        auto *ipv6 = reinterpret_cast<ip6_hdr *>(packet + ETH_HDR_LEN);
        dns_size = ntohs(ipv6->ip6_plen);
    }
    else {
        throw PcapException("internal error");
    }

    DEBUG_PRINT("TCP header\n");
    DEBUG_PRINT("    destination port = " + to_string(ntohs(tcp->dest)) + "\n");
    DEBUG_PRINT("    source port = " + to_string(ntohs(tcp->source)) + "\n");
    DEBUG_PRINT("    hdr_size = " + to_string(tcp->doff * 4) + "\n");
    DEBUG_PRINT("    size of TCP segment = " + to_string(dns_size) + "\n\n");

    // Copy memory of TCP segment
    auto *dns = reinterpret_cast<u_char *>(malloc(dns_size));
    memcpy(dns, tcp, dns_size);

    // Save the memory and its size to the pair
    pair <u_char *, u_int> elem;
    elem = make_pair(dns, dns_size);

    // Save pair to the vector
    m_tcp_buffer.push_back(elem);
}

void PcapParser::ipv4_handle(u_char *packet, u_int offset)
{
    ipv4_cnt++; // debug
    auto ipv4 = reinterpret_cast<ip *>(packet + offset);
    u_int ipv4_hdr_len = ipv4->ip_hl * 4;

    DEBUG_PRINT("IPv4 header\n");
    DEBUG_PRINT("    hdr_len: " + to_string(ipv4_hdr_len) + ", version: " + to_string(ipv4->ip_v));
    DEBUG_PRINT(", TTL: " + to_string(ipv4->ip_ttl) + "\n");
    DEBUG_PRINT("    IP dst = " + string(inet_ntoa(ipv4->ip_dst)) + "\n");
    DEBUG_PRINT("    IP src = " + string(inet_ntoa(ipv4->ip_src)) + "\n");
    DEBUG_PRINT("    Transport protocol: " + to_string(ipv4->ip_p) + "\n");

    // UDP packets
    if (ipv4->ip_p == IPPROTO_UDP) {
        udp_handle(packet, offset + ipv4_hdr_len);
    }
    // TCP packets
    else if (ipv4->ip_p == IPPROTO_TCP) {
        tcp_handle(packet, offset + ipv4_hdr_len);
    }
    else {
        not_udp_tcp_cnt++;
    }
}

void PcapParser::ipv6_handle(u_char *packet, u_int offset)
{
    ipv6_cnt++; // debug
    auto *ipv6 = reinterpret_cast<ip6_hdr *>(packet + offset);

    char src_ipv6[INET6_ADDRSTRLEN]; // debug
    char dst_ipv6[INET6_ADDRSTRLEN]; // debug
    inet_ntop(AF_INET6, &(ipv6->ip6_src), src_ipv6, INET6_ADDRSTRLEN); // debug
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), dst_ipv6, INET6_ADDRSTRLEN); // debug

    DEBUG_PRINT("IPv6 header\n");
    DEBUG_PRINT("    IP dst = " + string(dst_ipv6) + "\n");
    DEBUG_PRINT("    IP src = " + string(src_ipv6) + "\n");
    DEBUG_PRINT("    next header = " + to_string(ipv6->ip6_nxt) + "\n");

    // UDP packets
    if (ipv6->ip6_nxt == IPPROTO_UDP) {
        udp_handle(packet, offset + IPV6_HDR_LEN);
    }
    // TCP packets
    else if (ipv6->ip6_nxt == IPPROTO_TCP) {
        tcp_handle(packet, offset + IPV6_HDR_LEN);
    }
    else {
        not_udp_tcp_cnt++;
    }
}

void PcapParser::packet_handle(u_char *args, const pcap_pkthdr *packet_hdr, const u_char *packet)
{
    (void) args; (void) packet_hdr; // Stop yelling at me!
    frame_cnt++; // debug

    auto *eth = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));

    DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
    DEBUG_PRINT("Frame no. " + to_string(frame_cnt) + "\n");
    DEBUG_PRINT("Ethernet header\n");
    DEBUG_PRINT("    Length = " + to_string(packet_hdr->len) + "\n");
    DEBUG_PRINT("    Destination MAC = " + string(ether_ntoa((const struct ether_addr *) & eth->ether_dhost)) + "\n");
    DEBUG_PRINT("    Source MAC = " + string(ether_ntoa((const struct ether_addr *) & eth->ether_shost)) + "\n");

    // IPv4 datagrams
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        ipv4_handle(const_cast<u_char *>(packet), ETH_HDR_LEN);
    }
    // IPv6 datagrams
    else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) {
        ipv6_handle(const_cast<u_char *>(packet), ETH_HDR_LEN);
    }
    else {
        not_ipv4_ipv6_cnt++; // debug
    }
}

void PcapParser::set_resource(std::string resource)
{
    m_resource = resource;
}

void PcapParser::set_interface(std::string interface)
{
    m_interface = interface;
}

void PcapParser::parse_resource()
{
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};

    // Open the file for sniffing
    if ((handle = pcap_open_offline(m_resource.c_str(), error_buffer)) == nullptr) {
        throw PcapException("Couldn't open file " + m_resource + "\n" + error_buffer + "\n");
    }

    // Compile the filter
    if (pcap_compile(handle, &m_compiled_filter, m_filter_exp.c_str(), 0, 0) == PCAP_ERROR) {
        throw PcapException("Couldn't parse filter " + m_filter_exp + "\n" + pcap_geterr(handle) + "\n");
    }

    // Set the filter to the packet capture handle
    if (pcap_setfilter(handle, &m_compiled_filter) == PCAP_ERROR) {
        throw PcapException("Couldn't install filter " + m_filter_exp + "\n" + pcap_geterr(handle) + "\n");
    }

    // Read packets from the file in the infinite loop (count == 0)
    // Incoming packets are processed by function packet_handler()
    if (pcap_loop(handle, 0, packet_handle, nullptr) == PCAP_ERROR) {
        throw PcapException("Error occurs during pcap_loop\n" + string(pcap_geterr(handle)) + "\n");
    }
}

void PcapParser::sniff_interface()
{
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Get IP address and mask of the sniffing interface
    if (pcap_lookupnet(m_interface.c_str(), &net, &mask, error_buffer) == PCAP_ERROR) {
        throw PcapException("Couldn't get netmask for device " + m_interface + "\n" + error_buffer + "\n");
    }

    // Open the interface for live sniffing
    if ((handle = pcap_open_live(m_interface.c_str(), BUFSIZ, SNAPLEN, PROMISC, error_buffer)) == nullptr) {
        throw PcapException("Couldn't open device " + m_interface + "\n" + error_buffer + "\n");
    }

    // Compile the filter
    if (pcap_compile(handle, &m_compiled_filter, m_filter_exp.c_str(), 0, net) == PCAP_ERROR) {
        throw PcapException("Couldn't compile filter " + m_filter_exp + "\n" + pcap_geterr(handle) + "\n");
    }

    // Set the filter to the packet capture handle
    if (pcap_setfilter(handle, &m_compiled_filter) == PCAP_ERROR) {
        throw PcapException("Couldn't install filter " + m_filter_exp + "\n" + pcap_geterr(handle) + "\n");
    }

    // Read packets from the interface in the infinite loop (count == 0)
    // Incoming packets are processed by function packet_handler()
    if (pcap_loop(handle, 0, packet_handle, nullptr) == PCAP_ERROR) {
        throw PcapException("Error occurs during pcap_loop\n" + string(pcap_geterr(handle)) + "\n");
    }
}
