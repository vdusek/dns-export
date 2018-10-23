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
#include "dns_parser.h"

// Handle needs to be global because of signal handler
extern pcap_t *handle;

// Global constants
const int DIGEST_PRINT_LEN = 20;
const int SNAPLEN = 1;
const int PROMISC = 1000;
const u_int ETH_HDR_LEN = 14;
const u_int IPV6_HDR_LEN = 40;
const u_int UDP_HDR_LEN = 8;

/**
 * Parser of network frames.
 */
class PcapParser {
private:
    std::string m_filter_exp;
    bpf_program m_compiled_filter;
    std::string m_resource;
    std::string m_interface;

    /**
     * Handle UDP packet.
     */
    static void udp_handle(u_char *ptr);

    /**
     * Handle TCP packet.
     */
    static void tcp_handle(u_char *ptr);

    /**
     * Handle IPv4 datagram.
     */
    static void ipv4_handle(u_char *ptr);

    /**
     * Handle IPv6 datagram.
     */
    static void ipv6_handle(u_char *ptr);

    /**
     * Handle whole packet.
     */
    static void packet_handle(u_char *args, const pcap_pkthdr *packet_hdr, const u_char *packet);

public:
    /**
     * Constructor, set default members.
     */
    explicit PcapParser(std::string filter_exp);

    /**
     * Default destructor.
     */
    ~PcapParser();

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
