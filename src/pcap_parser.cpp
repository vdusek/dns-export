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
#include <arpa/inet.h>
#include <linux/udp.h>
#include <string>
#include "pcap_parser.h"
#include "dns_parser.h"
#include "utils.h"

using namespace std;

u_int frame_cnt = 0, // debug
      udp_cnt = 0, // debug
      tcp_cnt = 0, // debug
      ipv4_cnt = 0, // debug
      not_ipv4_cnt = 0; // debug

pcap_t *handle = nullptr;
DnsParser dns_parser;

PcapParser::PcapParser(string filter_exp):
    m_filter_exp(filter_exp),
    m_compiled_filter(),
    m_resource(""),
    m_interface("")
{
}

PcapParser::~PcapParser() = default;

void PcapParser::packet_handler(u_char *args, const pcap_pkthdr *packet_hdr, const u_char *packet)
{
    (void) args; (void) packet_hdr; // Stop yelling at me!

    ether_header *eth = nullptr;
    ip           *ip_ = nullptr;
    udphdr       *udp = nullptr;

    u_int ip_hdr_len;

    frame_cnt++;
    eth = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));

    // Filter just IPv4 frames
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        not_ipv4_cnt++;
        return;
    }
    ipv4_cnt++;

    ip_ = reinterpret_cast<ip *>(reinterpret_cast<u_char *>(eth) + ETH_HDR_LEN);
    ip_hdr_len = ip_->ip_hl * 4;


    DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
    DEBUG_PRINT("Frame no. " + to_string(frame_cnt) + "\n");
    DEBUG_PRINT("    Length: " + to_string(packet_hdr->len) + "\n");
    DEBUG_PRINT("    Source MAC: " + string(ether_ntoa((const struct ether_addr *) & eth->ether_shost)) + "\n");
    DEBUG_PRINT("    Destination MAC: " + string(ether_ntoa((const struct ether_addr *) & eth->ether_dhost)) + "\n");
    DEBUG_PRINT("    IP hdr_len: " + to_string(ip_hdr_len) + ", version: " + to_string(ip_->ip_v) + ", total length: "
                + to_string(ntohs(ip_->ip_len)) + ", TTL: " + to_string(ip_->ip_ttl) + "\n");
    DEBUG_PRINT("    IPv4 src = " + string(inet_ntoa(ip_->ip_src)) + "\n");
    DEBUG_PRINT("    IPv4 dst = " + string(inet_ntoa(ip_->ip_dst)) + "\n");
    DEBUG_PRINT("    Transport protocol: " + to_string(ip_->ip_p) + "\n\n");


    if (ip_->ip_p == IPPROTO_UDP) {
        udp_cnt++;
    }
    else if (ip_->ip_p == IPPROTO_TCP) {
        tcp_cnt++;

        // ToDo: implement TCP parsing
        DEBUG_PRINT("\nTCP PARSING... (ToDo)\n\n");
    }
    else {
        return;
    }

    udp = reinterpret_cast<udphdr *>(reinterpret_cast<u_char *>(ip_) + ip_hdr_len);

    dns_parser.parse(reinterpret_cast<u_char *>(udp) + UDP_HDR_LEN);
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
    if (pcap_loop(handle, 0, packet_handler, nullptr) == PCAP_ERROR) {
        throw PcapException("Error occurs during pcap_loop\n" + string(pcap_geterr(handle)) + "\n");
    }

    // Close the capture device and deallocate resources
    pcap_close(handle);

    DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
    DEBUG_PRINT("Summary:\n");
    DEBUG_PRINT("    Number of captured frames = " + to_string(frame_cnt) + "\n");
    DEBUG_PRINT("    Number of IPv4 datagrams = " + to_string(ipv4_cnt) + "\n");
    DEBUG_PRINT("    Number of other datagrams = " + to_string(not_ipv4_cnt) + "\n");
    DEBUG_PRINT("    Number of UDP packets = " + to_string(udp_cnt) + "\n");
    DEBUG_PRINT("    Number of TCP (not UDP) packets = " + to_string(tcp_cnt) + "\n");
    DEBUG_PRINT("    Number of DNS responses = " + to_string(dns_cnt) + "\n");
    DEBUG_PRINT("    Number of DNS answers = " + to_string(dns_ans_cnt) + "\n");
    DEBUG_PRINT("\n------------------------------------------------------------------------------\n\n");
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
    if (pcap_loop(handle, 0, packet_handler, nullptr) == PCAP_ERROR) {
        throw PcapException("Error occurs during pcap_loop\n" + string(pcap_geterr(handle)) + "\n");
    }

    // Close the capture device and deallocate resources
    pcap_close(handle);

    DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
    DEBUG_PRINT("Summary:\n");
    DEBUG_PRINT("    Number of captured frames = " + to_string(frame_cnt) + "\n");
    DEBUG_PRINT("    Number of IPv4 datagrams = " + to_string(ipv4_cnt) + "\n");
    DEBUG_PRINT("    Number of other datagrams = " + to_string(not_ipv4_cnt) + "\n");
    DEBUG_PRINT("    Number of UDP packets = " + to_string(udp_cnt) + "\n");
    DEBUG_PRINT("    Number of TCP (not UDP) packets = " + to_string(tcp_cnt) + "\n");
    DEBUG_PRINT("    Number of DNS responses = " + to_string(dns_cnt) + "\n");
    DEBUG_PRINT("    Number of DNS answers = " + to_string(dns_ans_cnt) + "\n");
    DEBUG_PRINT("\n------------------------------------------------------------------------------\n\n");
}
