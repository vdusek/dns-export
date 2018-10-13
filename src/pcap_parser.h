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

//// Bytes are already in network ordering, there's no need for ntohs()
//struct dns_flags_t {
//    char rd :1;                // recursion desired
//    char tc :1;                // truncated message
//    char aa :1;                // authoritive answer
//    char opcode :4;            // purpose of message, 0 for standard query
//    char qr :1;                // query (0) / response (1) flag
//    char rcode :4;             // response code, 0 if no error occurred
//    char z :3;                 // not used, reserved for the future
//    char ra :1;                // recursion available
//};

struct dns_header_t {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qd_count;
    u_int16_t an_count;
    u_int16_t ns_count;
    u_int16_t ar_count;
};

struct dns_query_t {
    // + name of the node whose resource records are being requested
    u_int16_t type;
    u_int16_t class_;
};

struct dns_answer_t {
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
void signal_handler(int sig);

class PcapParser {
private:
    std::string m_filename;
    std::string m_interface;

public:
    /**
     * Constructor.
     */
    PcapParser(std::string filename, std::string interface);

    /**
     * Destructor.
     */
    ~PcapParser();

    /**
     * Parse pcap file.
     */
    void parse_file();

    /**
     * Parse pcap file.
     */
    void parse_interface(u_int timeout);
};
