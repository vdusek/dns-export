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
#include <unordered_map>

#include "dns_parser.h"

// Handle needs to be global because of signal handler
extern pcap_t *handle;

// Global constants
const int DIGEST_PRINT_LEN = 20;
const int SNAPLEN = 1;
const int PROMISC = 1000;
const u_int ETH_HDR_LEN = 14;
const u_int UDP_HDR_LEN = 8;

/**
 * Parser of network frames.
 */
class PcapParser {
private:
    std::string m_filter_exp;
    bpf_program m_compiled_filter;

    /**
     * Packet handler.
     */
    static void packet_handler(u_char *args, const pcap_pkthdr *packet_hdr, const u_char *packet);

public:
    /**
     * Constructor.
     */
    explicit PcapParser(std::string filter_exp);

    /**
     * Default destructor.
     */
    ~PcapParser();

    /**
     * Parse pcap file.
     */
    void parse_file(std::string filename);

    /**
     * Sniff on the network interface.
     */
    void sniff_interface(std::string interface);
};
