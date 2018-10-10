// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.h

#pragma once

#include <string>
#include <pcap/pcap.h>

enum TypeDnsRecord {
    DNS_A = 1,
    DNS_AAAA = 28,
    DNS_CNAME = 5,
    DNS_DS = 43,
    DNS_MX = 15,
    DNS_NS = 2,
    DNS_NSEC = 47,
    DNS_PTR = 12,
    DNS_RRSIG = 46,
    DNS_SOA = 6,
    DNS_SPF = 99,
    DNS_TXT = 16
};

struct DnsHeader {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qd_count;
    u_int16_t an_count;
    u_int16_t ns_count;
    u_int16_t ar_count;
};

struct DnsQuery {
    // + name of the node whose resource records are being requested
    u_int16_t type;
    u_int16_t class_;
};

struct DnsAnswer {
    // + encoded name of the node to which this resource record applies
    u_int16_t type;
    u_int16_t class_;
    u_int32_t ttl;
    u_int16_t data_len;
    // + specific record data
};

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_hdr, const u_char *packet);
std::string read_name(u_char *dns_hdr, u_char *dns, u_int32_t *shift);
std::string read_ipv4(u_char *dns_reader);
std::string read_ipv6(u_char *dns_reader);

class PcapParser {
private:
    std::string m_filename;

public:
    /**
     * Constructor.
     */
    PcapParser(std::string filename);

    /**
     * Destructor.
     */
    ~PcapParser();

    /**
     * Parse pcap file.
     */
    void parse();
};
