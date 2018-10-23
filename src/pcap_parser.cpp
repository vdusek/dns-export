// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>
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

void PcapParser::udp_handle(u_char *packet)
{
    udp_cnt++; // debug

    auto *udp = reinterpret_cast<udphdr *>(packet);

    DEBUG_PRINT("UDP header\n");
    DEBUG_PRINT("    source port = " + to_string(ntohs(udp->source)) + "\n");
    DEBUG_PRINT("    destination port = " + to_string(ntohs(udp->dest)) + "\n");

    dns_parser.parse(reinterpret_cast<u_char *>(udp) + UDP_HDR_LEN);
}

void PcapParser::tcp_handle(u_char *packet)
{
    tcp_cnt++; // debug

    auto *tcp = reinterpret_cast<tcphdr *>(packet);

    // ToDo: implement tcp_handle

    DEBUG_PRINT("TCP header\n");
    DEBUG_PRINT("    source port = " + to_string(ntohs(tcp->source)) + "\n");
    DEBUG_PRINT("    destination port = " + to_string(ntohs(tcp->dest)) + "\n");
    DEBUG_PRINT("    payload = " + to_string(tcp->doff * 4) + "\n\n");
}

void PcapParser::ipv4_handle(u_char *packet)
{
    ipv4_cnt++; // debug

    auto ipv4 = reinterpret_cast<ip *>(packet);
    u_int ipv4_hdr_len = ipv4->ip_hl * 4;

    DEBUG_PRINT("IPv4 header\n");
    DEBUG_PRINT("    hdr_len: " + to_string(ipv4_hdr_len) + ", version: " + to_string(ipv4->ip_v));
    DEBUG_PRINT(", TTL: " + to_string(ipv4->ip_ttl) + "\n");
    DEBUG_PRINT("    IP src = " + string(inet_ntoa(ipv4->ip_src)) + "\n");
    DEBUG_PRINT("    IP dst = " + string(inet_ntoa(ipv4->ip_dst)) + "\n");
    DEBUG_PRINT("    Transport protocol: " + to_string(ipv4->ip_p) + "\n");

    // UDP packets
    if (ipv4->ip_p == IPPROTO_UDP) {
        udp_handle(reinterpret_cast<u_char *>(ipv4) + ipv4_hdr_len);
    }
    // TCP packets
    else if (ipv4->ip_p == IPPROTO_TCP) {
        tcp_handle(reinterpret_cast<u_char *>(ipv4) + ipv4_hdr_len);
    }
    else {
        not_udp_tcp_cnt++;
    }
}

void PcapParser::ipv6_handle(u_char *packet)
{
    ipv6_cnt++; // debug

    auto *ipv6 = reinterpret_cast<ip6_hdr *>(packet);

    char src_ipv6[INET6_ADDRSTRLEN]; // debug
    char dst_ipv6[INET6_ADDRSTRLEN]; // debug
    inet_ntop(AF_INET6, &(ipv6->ip6_src), src_ipv6, INET6_ADDRSTRLEN); // debug
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), dst_ipv6, INET6_ADDRSTRLEN); // debug

    DEBUG_PRINT("IPv6 header\n");
    DEBUG_PRINT("    IP src = " + string(src_ipv6) + "\n");
    DEBUG_PRINT("    IP dst = " + string(dst_ipv6) + "\n");
    DEBUG_PRINT("    next header = " + to_string(ipv6->ip6_nxt) + "\n");

    // UDP packets
    if (ipv6->ip6_nxt == IPPROTO_UDP) {
        udp_handle(reinterpret_cast<u_char *>(ipv6) + IPV6_HDR_LEN);
    }
    // TCP packets
    else if (ipv6->ip6_nxt == IPPROTO_TCP) {
        tcp_handle(reinterpret_cast<u_char *>(ipv6) + IPV6_HDR_LEN);
    }
    else {
        not_udp_tcp_cnt++;
    }
}

void PcapParser::packet_handle(u_char *args, const pcap_pkthdr *packet_hdr, const u_char *packet)
{
    (void) args; (void) packet_hdr; // Stop yelling at me!

    frame_cnt++;

    auto *eth = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));

    DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
    DEBUG_PRINT("Frame no. " + to_string(frame_cnt) + "\n");
    DEBUG_PRINT("Ethernet header\n");
    DEBUG_PRINT("    Length = " + to_string(packet_hdr->len) + "\n");
    DEBUG_PRINT("    Source MAC = " + string(ether_ntoa((const struct ether_addr *) & eth->ether_shost)) + "\n");
    DEBUG_PRINT("    Destination MAC = " + string(ether_ntoa((const struct ether_addr *) & eth->ether_dhost)) + "\n");

    // IPv4 datagrams
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        ipv4_handle(reinterpret_cast<u_char *>(eth) + ETH_HDR_LEN);
    }
    // IPv6 datagrams
    else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) {
        ipv6_handle(reinterpret_cast<u_char *>(eth) + ETH_HDR_LEN);
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
