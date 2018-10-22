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
#include <iostream>
#include <unordered_map>

#include "pcap_parser.h"
#include "dns_parser.h"
#include "utils.h"

using namespace std;

// debug
u_int pck_cnt = 0,
      dns_cnt = 0,
      udp_cnt = 0,
      not_udp_cnt = 0,
      ipv4_cnt = 0,
      not_ipv4_cnt = 0;

pcap_t *handle = nullptr;
DnsParser dns_parser;

PcapParser::PcapParser(string filter_exp):
    m_filter_exp(filter_exp),
    m_compiled_filter()
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

    pck_cnt++;
    eth = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));

    // Filter just IPv4 frames
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        not_ipv4_cnt++;
        return;
    }
    ipv4_cnt++;

    ip_ = reinterpret_cast<ip *>(reinterpret_cast<u_char *>(eth) + ETH_HDR_LEN);
    ip_hdr_len = ip_->ip_hl * 4;

    // Filter just UDP communication
    if (ip_->ip_p == IPPROTO_UDP) {
        udp_cnt++;
    }
    else {
        // ToDo: parse TCP packets as well!
        not_udp_cnt++;
        return;
    }

    udp = reinterpret_cast<udphdr *>(reinterpret_cast<u_char *>(ip_) + ip_hdr_len);

    fprintf(stderr, "------------------------------------------------------------------------------\n\n");
    fprintf(stderr, "Packet no. %d\n", pck_cnt);
    fprintf(stderr, "    Length: %d\n", packet_hdr->len);
    fprintf(stderr, "    Source MAC: %s\n", ether_ntoa((const struct ether_addr *) & eth->ether_shost));
    fprintf(stderr, "    Destination MAC: %s\n", ether_ntoa((const struct ether_addr *) & eth->ether_dhost));
    fprintf(stderr, "    Ethernet type: 0x%x (IP packet)\n", ntohs(eth->ether_type));
    fprintf(stderr, "    IP: hlen %d bytes, version %d, total length %d bytes, TTL %d\n", ip_hdr_len,
            ip_->ip_v, ntohs(ip_->ip_len), ip_->ip_ttl);
    fprintf(stderr, "    IP src = %s, ", inet_ntoa(ip_->ip_src));
    fprintf(stderr, "IP dst = %s", inet_ntoa(ip_->ip_dst));
    fprintf(stderr, ", protocol UDP (%d)\n\n", ip_->ip_p);

    dns_cnt++;
    dns_parser.parse(reinterpret_cast<u_char *>(udp) + UDP_HDR_LEN);
}

void PcapParser::parse_file(std::string filename)
{
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};

    // Open the file for sniffing
    if ((handle = pcap_open_offline(filename.c_str(), error_buffer)) == nullptr) {
        throw PcapException("Couldn't open file " + filename + "\n" + error_buffer + "\n");
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

    cerr << endl;
    cerr << "Summary: " << endl;
    cerr << "    Number of captured packets = " << pck_cnt << endl;
    cerr << "    Number of IPv4 datagrams = " << ipv4_cnt << endl;
    cerr << "    Number of other datagrams = " << not_ipv4_cnt << endl;
    cerr << "    Number of UDP packets = " << udp_cnt<< endl;
    cerr << "    Number of TCP (not UDP) packets = " << not_udp_cnt << endl;
    cerr << "    Number of DNS packets = " << dns_cnt << endl;
    cerr << "    Number of DNS answers = " << dns_ans_cnt << endl;
    cerr << "=======================================================================" << endl;
}

void PcapParser::sniff_interface(std::string interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Get IP address and mask of the sniffing interface
    if (pcap_lookupnet(interface.c_str(), &net, &mask, error_buffer) == PCAP_ERROR) {
        throw PcapException("Couldn't get netmask for device " + interface + "\n" + error_buffer + "\n");
    }

    // Open the interface for live sniffing
    if ((handle = pcap_open_live(interface.c_str(), BUFSIZ, SNAPLEN, PROMISC, error_buffer)) == nullptr) {
        throw PcapException("Couldn't open device " + interface + "\n" + error_buffer + "\n");
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

    cerr << endl;
    cerr << "Summary: " << endl;
    cerr << "    Number of captured packets = " << pck_cnt << endl;
    cerr << "    Number of IPv4 datagrams = " << ipv4_cnt << endl;
    cerr << "    Number of other datagrams = " << not_ipv4_cnt << endl;
    cerr << "    Number of UDP packets = " << udp_cnt<< endl;
    cerr << "    Number of TCP (not UDP) packets = " << not_udp_cnt << endl;
    cerr << "    Number of DNS packets = " << dns_cnt << endl;
    cerr << "    Number of DNS answers = " << dns_ans_cnt << endl;
    cerr << "=======================================================================" << endl;
}
