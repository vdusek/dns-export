// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: dns_parser.h

#pragma once

#include <sys/param.h>

#include <string>
#include <unordered_map>

// debug
extern int dns_ans_cnt;

/**
 * Types of DNS records.
 */
enum TypeDnsRecord {
    DNS_A = 1,
    DNS_AAAA = 28,
    DNS_CNAME = 5,
    DNS_DNSKEY = 48,
    DNS_DS = 43,
    DNS_MX = 15,
    DNS_NS = 2,
    DNS_NSEC = 47,
    DNS_OPT = 41,
    DNS_PTR = 12,
    DNS_RRSIG = 46,
    DNS_SOA = 6,
    DNS_SPF = 99,
    DNS_TXT = 16
    // ToDo: add more types
};

/**
 * Types of DNSSEC algorithms.
 */
enum DnsSecAlgorithmType {
    DNSSEC_DELETE = 0,
    DNSSEC_RSAMD5 = 1,
    DNSSEC_DH = 2,
    DNSSEC_DSA = 3,
    DNSSEC_RSASHA1 = 5,
    DNSSEC_DSA_NSEC3_SHA1 = 6,
    DNSSEC_RSASHA1_NSEC3_SHA1 = 7,
    DNSSEC_RSASHA256 = 8,
    DNSSEC_RSASHA512 = 10,
    DNSSEC_ECC_GOST = 12,
    DNSSEC_ECDSAP256SHA256 = 13,
    DNSSEC_ECDSAP384SHA384 = 14,
    DNSSEC_ED25519 = 15,
    DNSSEC_ED448 = 16,
    DNSSEC_INDIRECT = 252,
    DNSSEC_PRIVATEDNS = 253,
    DNSSEC_PRIVATEOID = 254
    // Other values (between 0-255) are reserved or unassigned
};

/**
 * Types of DNSSEC digests.
 */
enum DnsSecDigestType {
    DNSSECDIGEST_RESERVED = 0,
    DNSSECDIGEST_SHA1 = 1,
    DNSSECDIGEST_SHA256 = 2,
    DNSSECDIGEST_GOSTR = 3,
    DNSSECDIGEST_SHA384 = 4,
    // Other values (between 0-255) are unassigned
};

/**
 * Structure of DNS header.
 */
struct __attribute__((packed)) dns_header_t {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qd_count;
    u_int16_t an_count;
    u_int16_t ns_count;
    u_int16_t ar_count;
};

/**
 * Structure of DNS header flags.
 */
struct __attribute__((packed)) dns_header_flags_t {
    // Bytes are already in network ordering, there's no need for their reverse.
    char rd :1;                // recursion desired
    char tc :1;                // truncated message
    char aa :1;                // authoritive answer
    char opcode :4;            // purpose of message, 0 for standard query
    char qr :1;                // query (0) / response (1) flag
    char rcode :4;             // response code, 0 if no error occurred
    char z :3;                 // not used, reserved for the future
    char ra :1;                // recursion available
};

/**
 * Structure of DNS query.
 */
struct __attribute__((packed)) dns_query_t {
    // + name of the node whose resource records are being requested
    u_int16_t type;
    u_int16_t class_;
};

/**
 * Structure of DNS resource record.
 */
struct __attribute__((packed)) dns_rr_t {
    // + encoded name of the node to which this resource record applies
    u_int16_t type;
    u_int16_t class_;
    u_int32_t ttl;
    u_int16_t data_len;
    // + specific record data
};

/**
 * Structure of DNS resource data MX type.
 */
struct __attribute__((packed)) dns_rd_mx_t {
    u_int16_t preference;
    // exchange
};

/**
 * Structure of DNS resource data SOA type.
 */
struct __attribute__((packed)) dns_rd_soa_t {
    // + mname
    // + rname
    u_int32_t serial;
    u_int32_t refresh;
    u_int32_t retry;
    u_int32_t expire;
    u_int32_t minimum;
};

/**
 * Structure of DNS resource data RRSIG type.
 */
struct __attribute__((packed)) dns_rd_rrsig_t {
    u_int16_t type_covered;
    u_char algorithm;
    u_char labels;
    u_int32_t original_ttl;
    u_int32_t signature_expiration;
    u_int32_t signature_inception;
    u_int16_t key_tag;
    // + Signer's Name
    // + Signature
};

/**
 * Structure of DNS resource data DS type.
 */
struct __attribute__((packed)) dns_rd_ds_t {
    u_int16_t key_tag;
    u_char algorithm;
    u_char digest_type;
    // + Digest
};

/**
 * Structure of DNS resource data DNSKEY type.
 */
struct __attribute__((packed)) dns_rd_dnskey_t {
    u_int16_t flags;
    u_char protocol;
    u_char algorithm;
    // + public key
};

/**
 * Parser of DNS packets.
 */
class DnsParser {
public:
    /**
     * Default constructor.
     */
    DnsParser();

    /**
     * Default destructor.
     */
    ~DnsParser();

    /**
     * Parse DNS packets.
     */
    void parse(u_char *packet);

    /**
     * Convert enum TypeDnsRecord to string.
     */
    std::string resource_type_to_str(TypeDnsRecord type_dns_record);

    /**
     * Convert enum DnsSecAlgorithmType to string.
     */
    std::string algorithm_type_to_str(DnsSecAlgorithmType dnssec_algorithm_type);

    /**
     * Convert enum DnsSecDigestType to string.
     */
    std::string digest_type_to_str(DnsSecDigestType dnssec_digest_type);

    /**
     * Parse record A (IPv4).
     */
    std::string parse_record_a(u_char *dns);

    /**
     * Parse record AAAA (IPv6).
     */
    std::string parse_record_aaaa(u_char *dns);

    /**
     * Parse record CNAME.
     */
    std::string parse_record_cname(u_char *dns_hdr, u_char *dns);

    /**
     * Parse record DNSKEY.
     */
    std::string parse_record_dnskey(u_char *dns, u_int data_len);

    /**
     * Parse record DS.
     */
    std::string parse_record_ds(u_char *dns, u_int data_len);

    /**
     * Parse record MX.
     */
    std::string parse_record_mx(u_char *dns_hdr, u_char *dns);

    /**
     * Parse record NS.
     */
    std::string parse_record_ns(u_char *dns_hdr, u_char *dns);

    /**
     * Parse record NSEC.
     */
    std::string parse_record_nsec(u_char *dns_hdr, u_char *dns);

    /**
     * Parse record OPT.
     */
    std::string parse_record_opt();

    /**
     * Parse record PTR.
     */
    std::string parse_record_ptr(u_char *dns_hdr, u_char *dns);

    /**
     * Parse record RRSIG.
     */
    std::string parse_record_rrsig(u_char *dns_hdr, u_char *dns, u_int data_len);

    /**
     * Parse record SOA.
     */
    std::string parse_record_soa(u_char *dns_hdr, u_char *dns);

    /**
     * Parse record TXT/SPF.
     */
    std::string parse_record_txt_spf(u_char *dns);
};
