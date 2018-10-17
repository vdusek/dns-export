// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <unistd.h>
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


PcapParser::PcapParser():
    m_filter_exp("port 53"),
    m_compiled_filter()
{
}

PcapParser::~PcapParser() = default;

void PcapParser::packet_handler(u_char *args, const struct pcap_pkthdr *packet_hdr, const u_char *packet)
{
    (void) args; (void) packet_hdr; // Stop yelling at me!

    ether_header *eth = nullptr;
    ip           *ip_ = nullptr;
    udphdr       *udp = nullptr;

    const u_int eth_len     = 14,
                udp_len     = 8;

    u_int ip_len;
    string record;

    pck_cnt++; // debug
    eth = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));

    /* Filter just IPv4 frames */
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        not_ipv4_cnt++;
        cerr << "Not an IP frame" << endl;
        return;
    }
    ipv4_cnt++;

    ip_ = reinterpret_cast<ip *>(reinterpret_cast<char *>(eth) + eth_len);
    ip_len = ip_->ip_hl * 4;

    /* Filter just UDP communication */
    // ToDo: parse TCP packets as well
    if (ip_->ip_p == IPPROTO_UDP) {
        udp_cnt++;
    }
    else {
        not_udp_cnt++;
        cerr << "Not an UDP datagram" << endl;
        return;
    }

    udp = reinterpret_cast<udphdr *>(reinterpret_cast<char *>(ip_) + ip_len);

    fprintf(stderr, "------------------------------------------------------------------------------\n\n");
    fprintf(stderr, "Packet no. %d\n", pck_cnt);
    fprintf(stderr, "    Length: %d\n", packet_hdr->len);
    fprintf(stderr, "    Source MAC: %s\n", ether_ntoa((const struct ether_addr *) & eth->ether_shost));
    fprintf(stderr, "    Destination MAC: %s\n", ether_ntoa((const struct ether_addr *) & eth->ether_dhost));
    fprintf(stderr, "    Ethernet type: 0x%x (IP packet)\n", ntohs(eth->ether_type));
    fprintf(stderr, "    IP: hlen %d bytes, version %d, total length %d bytes, TTL %d\n", ip_len,
            ip_->ip_v, ntohs(ip_->ip_len), ip_->ip_ttl);
    fprintf(stderr, "    IP src = %s, ", inet_ntoa(ip_->ip_src));
    fprintf(stderr, "IP dst = %s", inet_ntoa(ip_->ip_dst));
    fprintf(stderr, ", protocol UDP (%d)\n\n", ip_->ip_p);

    dns_cnt++;
    dns_parser.parse(reinterpret_cast<u_int8_t *>(udp) + udp_len);
}

void PcapParser::parse_file(std::string filename)
{
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};

    signal(SIGUSR1, signal_handler);

    // Open the file for sniffing
    if ((handle = pcap_open_offline(filename.c_str(), error_buffer)) == nullptr) {
        fprintf(stderr, "Could not open file %s: %s\n", filename.c_str(), error_buffer);
        return;
    }

    // Compile the filter
    if (pcap_compile(handle, &m_compiled_filter, m_filter_exp.c_str(), 0, 0) == EOF) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", m_filter_exp.c_str(), pcap_geterr(handle));
        return;
    }

    // Set the filter to the packet capture handle
    if (pcap_setfilter(handle, &m_compiled_filter) == EOF) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", m_filter_exp.c_str(), pcap_geterr(handle));
        return;
    }

    // Read packets from the file in the infinite loop (count == 0)
    // Incoming packets are processed by function packet_handler()
    pcap_loop(handle, 0, packet_handler, nullptr);

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

void PcapParser::parse_interface(std::string interface, u_int timeout)
{
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};
    alarm(timeout);
    signal(SIGALRM, signal_handler);
    signal(SIGUSR1, signal_handler);

    bpf_u_int32 mask;          /* The netmask of our sniffing device */
    bpf_u_int32 net;           /* The IP of our sniffing device */

    // Get IP address and mask of the sniffing interface
    if (pcap_lookupnet(interface.c_str(), &net, &mask, error_buffer) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", interface.c_str());
        net = 0;
        mask = 0;
        return;
    }

    // Open the interface for live sniffing
    if ((handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, error_buffer)) == nullptr) {
        fprintf(stderr, "Could not open device %s: %s\n", interface.c_str(), error_buffer);
        return;
    }

    // Compile the filter
    if (pcap_compile(handle, &m_compiled_filter, m_filter_exp.c_str(), 0, net) == EOF) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", m_filter_exp.c_str(), pcap_geterr(handle));
        return;
    }

    // Set the filter to the packet capture handle
    if (pcap_setfilter(handle, &m_compiled_filter) == EOF) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", m_filter_exp.c_str(), pcap_geterr(handle));
        return;
    }

    // Read packets from the interface in the infinite loop (count == 0)
    // Incoming packets are processed by function packet_handler()
    pcap_loop(handle, 0, packet_handler, nullptr);

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
