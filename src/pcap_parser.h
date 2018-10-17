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

extern pcap_t *handle;

class PcapParser {
private:
    std::string m_filter_exp;
    bpf_program m_compiled_filter;
public:
    /**
     * Constructor.
     */
    explicit PcapParser(std::string filter_exp);

    /**
     * Empty destructor.
     */
    ~PcapParser();

    /**
     * Packet handler.
     */
    static void packet_handler(u_char *args, const pcap_pkthdr *packet_hdr, const u_char *packet);

    /**
     * Parse pcap file.
     */
    void parse_file(std::string filename);

    /**
     * Sniff on the interface till timeout.
     */
    void parse_interface(std::string interface, u_int timeout);
};
