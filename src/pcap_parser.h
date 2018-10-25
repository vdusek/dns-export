// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.h

#pragma once

#include <pcap/pcap.h>
#include <string>
#include <vector>
#include "dns_parser.h"

// Extern debug counters
extern u_int frame_cnt;
extern u_int udp_cnt;
extern u_int tcp_cnt;
extern u_int not_udp_tcp_cnt;
extern u_int ipv4_cnt;
extern u_int ipv6_cnt;
extern u_int not_ipv4_ipv6_cnt;

// Handle of pcap resource is global because of signal handler
extern pcap_t *handle;

/**
 * Parser of network frames using pcap lib.
 */
class PcapParser {
private:
    std::string m_filter_exp;
    bpf_program m_compiled_filter;
    std::string m_resource;
    std::string m_interface;
    static std::vector<std::pair <u_char *, u_int>> m_tcp_buffer;

    /**
     * Handle UDP packet.
     */
    static void udp_handle(u_char *packet, u_int offset);

    /**
     * Handle TCP packet.
     */
    static void tcp_handle(u_char *packet, u_int offset);

    /**
     * Handle IPv4 datagram.
     */
    static void ipv4_handle(u_char *packet, u_int offset);

    /**
     * Handle IPv6 datagram.
     */
    static void ipv6_handle(u_char *packet, u_int offset);

    /**
     * Handle ethernet frame.
     */
    static void packet_handle(u_char *args, const pcap_pkthdr *packet_hdr, const u_char *packet);

public:
    /**
     * Constructor, set default members.
     */
    explicit PcapParser(std::string filter_exp);

    /**
     * Destructor, close the capture device and deallocate resources.
     */
    ~PcapParser();

    /**
     * Parse TCP packets and call DNS parse.
     */
    void parse_tcp();

    /**
     * Set resource name.
     */
    void set_resource(std::string resource);

    /**
     * Set interface name.
     */
    void set_interface(std::string interface);

    /**
     * Parse resource (.pcap file).
     */
    void parse_resource();

    /**
     * Sniff on the network interface.
     */
    void sniff_interface();
};
