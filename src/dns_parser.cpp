// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: dns_parser.cpp

#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#include <string>
#include <iostream>
#include <bitset>
#include <unordered_map>
#include <ctime>

#include "utils.h"
#include "dns_parser.h"
#include "pcap_parser.h"

using namespace std;

// debug
int rr_count_total = 0;
int dns_ans_cnt = 0;

DnsParser::DnsParser() = default;

DnsParser::~DnsParser() = default;

void DnsParser::parse(u_char *packet)
{
    dns_header_t *dns_hdr = nullptr;
    dns_rr_t     *dns_rr  = nullptr;
    u_char       *dns     = nullptr;

    string name, type, data, record;

    u_int shift;

    dns_hdr = reinterpret_cast<dns_header_t *>(packet);

    // Filter just responses
    if (!(ntohs(dns_hdr->flags) & 0b1000000000000000)) {
        return;
    }

    // Filter just no error responses
    if (ntohs(dns_hdr->flags) & 0b0000000000001111) {
        return;
    }

    // Filter just responses with 1 question, others make no sense
    if (ntohs(dns_hdr->qd_count) != 1) {
        return;
    }

    // debug
    fprintf(stderr, "DNS header\n");
    fprintf(stderr, "    id = 0x%04x\n", ntohs(dns_hdr->id));
    fprintf(stderr, "    flags = 0x%04x\n", ntohs(dns_hdr->flags));
    fprintf(stderr, "    qd_count = %d\n", ntohs(dns_hdr->qd_count));
    fprintf(stderr, "    an_count = %d\n", ntohs(dns_hdr->an_count));
    fprintf(stderr, "    ns_count = %d\n", ntohs(dns_hdr->ns_count));
    fprintf(stderr, "    ar_count = %d\n\n", ntohs(dns_hdr->ar_count));

    dns = reinterpret_cast<u_char *>(dns_hdr) + sizeof(dns_header_t);

    // Skip query (name + sizeof(query)
    while (*(++dns) != '\0');
    dns += (1 + sizeof(dns_query_t));

    // ToDo: go through all type of resource records?
    int rr_count = ntohs(dns_hdr->an_count) + ntohs(dns_hdr->ns_count) + ntohs(dns_hdr->ar_count);
    rr_count_total += rr_count;

    // For every resource record
    for (int i = 0; i < rr_count; i++) {
        dns_ans_cnt++;

        fprintf(stderr, "DNS answer (%d)\n", i + 1);

        name = read_domain_name(reinterpret_cast<u_char *>(dns_hdr), dns, &shift);

        fprintf(stderr, "    domain_name = %s\n", name.c_str());

        dns += shift;
        dns_rr = reinterpret_cast<dns_rr_t *>(dns);

        fprintf(stderr, "    type = %d\n", ntohs(dns_rr->type));
        fprintf(stderr, "    class = %d\n", ntohs(dns_rr->class_));
        fprintf(stderr, "    ttl = %d\n", ntohl(dns_rr->ttl));
        fprintf(stderr, "    data_len = %d\n", ntohs(dns_rr->data_len));

        dns += sizeof(dns_rr_t);

        switch (ntohs(dns_rr->type)) {

            case DNS_A:
                data = parse_record_a(dns);
                type = "A";
                break;

            case DNS_AAAA:
                data = parse_record_aaaa(dns);
                type = "AAAA";
                break;

            case DNS_CNAME:
                data = parse_record_cname(reinterpret_cast<u_char *>(dns_hdr), dns);
                type = "CNAME";
                break;

            // ToDo: test this case
            case DNS_DNSKEY:
                data = parse_record_dnskey(dns, ntohs(dns_rr->data_len));
                type = "DNSKEY";
                break;

            case DNS_DS:
                data = parse_record_ds(dns, ntohs(dns_rr->data_len));
                type = "DS";
                break;

            case DNS_MX:
                data = parse_record_mx(reinterpret_cast<u_char *>(dns_hdr), dns);
                type = "MX";
                break;

            case DNS_NS:
                data = parse_record_ns(reinterpret_cast<u_char *>(dns_hdr), dns);
                type = "NS";
                break;

            case DNS_NSEC:
                data = parse_record_nsec(reinterpret_cast<u_char *>(dns_hdr), dns);
                type = "NSEC";
                break;

            case DNS_OPT:
                data = parse_record_opt();
                type = "OPT";
                return;

            case DNS_PTR:
                data = parse_record_ptr(reinterpret_cast<u_char *>(dns_hdr), dns);
                type = "PTR";
                break;

            case DNS_RRSIG:
                data = parse_record_rrsig(reinterpret_cast<u_char *>(dns_hdr), dns, ntohs(dns_rr->data_len));
                type = "RRSIG";
                break;

            case DNS_SOA:
                data = parse_record_soa(reinterpret_cast<u_char *>(dns_hdr), dns);
                type = "SOA";
                break;

            // ToDo: test this case
            case DNS_SPF:
                data = parse_record_txt_spf(dns);
                type = "SPF";
                break;

            // ToDo: test this case
            case DNS_TXT:
                data = parse_record_txt_spf(dns);
                type = "TXT";
                break;

            // ToDo: when unknown DNS record, maybe throw away whole packet, it could cause a problem
            default:
                data = "unknown_data";
                type = "unknown_type";
                break;
        }
        dns += ntohs(dns_rr->data_len);

        fprintf(stderr, "    data = %s\n", data.c_str()); // debug
        cerr << "RESULT:\n" << name << " " << type << " " << data << endl << endl; // debug

        record = name.append(" ") + type.append(" ") + data.append(" ");

        auto search = result_map.find(record);

        if (search != result_map.end()) {
            result_map[record]++;
        }
        else {
            result_map[record] = 1;
        }
    }
}

string DnsParser::resource_type_to_str(TypeDnsRecord type_dns_record)
{
    switch (type_dns_record) {
        case DNS_A:
            return "A";
        case DNS_AAAA:
            return "AAAA";
        case DNS_CNAME:
            return "CNAME";
        case DNS_DNSKEY:
            return "DNSKEY";
        case DNS_DS:
            return "DS";
        case DNS_MX:
            return "MX";
        case DNS_NS:
            return "NS";
        case DNS_NSEC:
            return "NSEC";
        case DNS_OPT:
            return "OPT";
        case DNS_PTR:
            return "PTR";
        case DNS_RRSIG:
            return "RRSIG";
        case DNS_SOA:
            return "SOA";
        case DNS_SPF:
            return "SPF";
        case DNS_TXT:
            return "TXT";
        default:
            return "unknown";
    }
}

string DnsParser::algorithm_type_to_str(DnsSecAlgorithmType dnssec_algorithm_type)
{
    switch (dnssec_algorithm_type) {
        case DNSSEC_DELETE:
            return "delete";
        case DNSSEC_RSAMD5:
            return "RSA/MD5";
        case DNSSEC_DH:
            return "Diffie-Hellman";
        case DNSSEC_DSA:
            return "DSA/SHA-1";
        case DNSSEC_RSASHA1:
            return "RSA/SHA-1";
        case DNSSEC_DSA_NSEC3_SHA1:
            return "DSA-NSEC3-SHA1";
        case DNSSEC_RSASHA1_NSEC3_SHA1:
            return "RSASHA1-NSEC3-SHA1";
        case DNSSEC_RSASHA256:
            return "RSA/SHA-256";
        case DNSSEC_RSASHA512:
            return "RSA/SHA-512";
        case DNSSEC_ECC_GOST:
            return "GOST R 34.10-2001";
        case DNSSEC_ECDSAP256SHA256:
            return "ECDSA Curve P-256 with SHA-256";
        case DNSSEC_ECDSAP384SHA384:
            return "ECDSA Curve P-384 with SHA-384";
        case DNSSEC_ED25519:
            return "Ed25519";
        case DNSSEC_ED448:
            return "Ed448";
        case DNSSEC_INDIRECT:
            return "Reserved for Indirect Keys";
        case DNSSEC_PRIVATEDNS:
            return "private algorithm";
        case DNSSEC_PRIVATEOID:
            return "private algorithm OID";
        default:
            return "unassigned/reserved";
    }
}

string DnsParser::digest_type_to_str(DnsSecDigestType dnssec_digest_type)
{
    switch (dnssec_digest_type) {
        case DNSSECDIGEST_RESERVED:
            return "reserved";
        case DNSSECDIGEST_SHA1:
            return "SHA-1";
        case DNSSECDIGEST_SHA256:
            return "SHA-256";
        case DNSSECDIGEST_GOSTR:
            return "GOST R 34.11-94";
        case DNSSECDIGEST_SHA384:
            return "SHA-384";
        default:
            return "unassigned";
    }
}

string DnsParser::parse_record_a(u_char *dns)
{
    in_addr address;
    memcpy(&address, dns, sizeof(address));
    char ipv4[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &address, ipv4, INET_ADDRSTRLEN);
    return static_cast<string> (ipv4);
}

string DnsParser::parse_record_aaaa(u_char *dns)
{
    in6_addr address;
    memcpy(&address, dns, sizeof(address));
    char ipv6[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &address, ipv6, INET6_ADDRSTRLEN);
    return static_cast<string> (ipv6);
}

string DnsParser::parse_record_cname(u_char *dns_hdr, u_char *dns)
{
    u_int shift;
    return read_domain_name(dns_hdr, dns, &shift);
}

string DnsParser::parse_record_dnskey(u_char *dns, u_int data_len)
{
    string data;
    auto *dns_rd_dnskey = reinterpret_cast<dns_rd_dnskey_t *>(dns);

    data.append(bin_to_hexa(reinterpret_cast<u_char *>(&dns_rd_dnskey->flags), sizeof(dns_rd_dnskey->flags)).append(" "));
    data.append(to_string(dns_rd_dnskey->protocol));
    data.append(algorithm_type_to_str(static_cast<DnsSecAlgorithmType>(dns_rd_dnskey->algorithm)).append(" "));

    dns += sizeof(dns_rd_dnskey_t);

    data.append(bin_to_hexa(dns, data_len - sizeof(dns_rd_ds_t)).substr(0, DIGEST_PRINT_LEN).append("..."));

    return data;
}

string DnsParser::parse_record_ds(u_char *dns, u_int data_len)
{
    string data;
    auto *dns_rd_ds = reinterpret_cast<dns_rd_ds_t *>(dns);

    data.append(bin_to_hexa(reinterpret_cast<u_char *>(&dns_rd_ds->key_tag), sizeof(dns_rd_ds->key_tag)).append(" "));
    data.append(algorithm_type_to_str(static_cast<DnsSecAlgorithmType>(dns_rd_ds->algorithm)).append(" "));
    data.append(digest_type_to_str(static_cast<DnsSecDigestType>(dns_rd_ds->digest_type)).append(" "));

    dns += sizeof(dns_rd_ds_t);

    data.append(bin_to_hexa(dns, data_len - sizeof(dns_rd_ds_t)).substr(0, DIGEST_PRINT_LEN).append("..."));

    return data;
}

string DnsParser::parse_record_mx(u_char *dns_hdr, u_char *dns)
{
    string data;
    u_int shift;

    auto *dns_rd_mx = reinterpret_cast<dns_rd_mx_t *>(dns);

    data = to_string(ntohs(dns_rd_mx->preference)).append(" ");
    data.append(read_domain_name(dns_hdr, dns + sizeof(dns_rd_mx_t), &shift));

    return data;
}

string DnsParser::parse_record_ns(u_char *dns_hdr, u_char *dns)
{
    u_int shift;
    return read_domain_name(dns_hdr, dns, &shift);
}

string DnsParser::parse_record_nsec(u_char *dns_hdr, u_char *dns)
{
    string data;
    u_int shift;

    data = read_domain_name(dns_hdr, dns, &shift).append(" ");
    dns += shift;

    string bit_maps_field;

    u_int16_t num_bytes = ntohs(*reinterpret_cast<u_int16_t *>(dns));
    dns += 2;

    bitset<8> byte;

    // 0 - 7
    if (num_bytes > 0) {
        byte = bitset<8>(reverse_bits(*dns));
        if (byte.test(1))
            bit_maps_field.append("A ");
        if (byte.test(2))
            bit_maps_field.append("NS ");
        if (byte.test(5))
            bit_maps_field.append("CNAME ");
        if (byte.test(6))
            bit_maps_field.append("SOA ");
    }
    dns++;

    // 8 - 15
    if (num_bytes > 1) {
        byte = bitset<8>(reverse_bits(*dns));
        if (byte.test(4))
            bit_maps_field.append("PTR ");
        if (byte.test(7))
            bit_maps_field.append("MX ");
    }
    dns++;

    // 16 - 23
    if (num_bytes > 2) {
        byte = bitset<8>(reverse_bits(*dns));
        if (byte.test(0))
            bit_maps_field.append("TXT ");
    }
    dns++;

    // 24 - 31
    if (num_bytes > 3) {
        byte = bitset<8>(reverse_bits(*dns));
        if (byte.test(4))
            bit_maps_field.append("AAAA ");
    }
    dns++;

    // 32 - 39
    dns++;

    // 40 - 47
    if (num_bytes > 5) {
        byte = bitset<8>(reverse_bits(*dns));
        if (byte.test(3))
            bit_maps_field.append("DS ");
        if (byte.test(6))
            bit_maps_field.append("RRSIG ");
        if (byte.test(7))
            bit_maps_field.append("NSEC ");
    }
    dns++;

    // 48 - 55
    if (num_bytes > 6) {
        byte = bitset<8>(reverse_bits(*dns));
        if (byte.test(0))
            bit_maps_field.append("DNSKEY ");
    }
    dns++;

    // 56 - 63
    dns++;

    // 64 - 71
    dns++;

    // 72 - 79
    dns++;

    // 80 - 87
    dns++;

    // 88 - 95
    dns++;

    // 96 - 103
    if (num_bytes > 12) {
        byte = bitset<8>(reverse_bits(*dns));
        if (byte.test(3))
            bit_maps_field.append("SPF ");
    }

    // ToDo: determine more types of DNS records?

    data.append(bit_maps_field);

    return data;
}

string DnsParser::parse_record_opt()
{
    return "<Root>";
}

// ToDo:
//   - it's IP address -> domain name
//   - so the IP address is probably not read in the right way
string DnsParser::parse_record_ptr(u_char *dns_hdr, u_char *dns)
{
    u_int shift;
    return read_domain_name(dns_hdr, dns, &shift);
}

// ToDo:
//   - RRSIG results are not 100% correct, filter and debug it
string DnsParser::parse_record_rrsig(u_char *dns_hdr, u_char *dns, u_int data_len)
{
    string data;
    u_int shift;

    auto *dns_rd_rrsig = reinterpret_cast<dns_rd_rrsig_t *>(dns);

    data.append(resource_type_to_str(static_cast<TypeDnsRecord>(ntohs(dns_rd_rrsig->type_covered))).append(" "));
    data.append(algorithm_type_to_str((static_cast<DnsSecAlgorithmType>(dns_rd_rrsig->algorithm))).append(" "));
    data.append(to_string(dns_rd_rrsig->labels).append(" "));
    data.append(to_string(ntohl(dns_rd_rrsig->original_ttl)).append(" "));
    data.append(bin_to_time(ntohl(dns_rd_rrsig->signature_expiration))).append(" ");
    data.append(bin_to_time(ntohl(dns_rd_rrsig->signature_inception))).append(" ");
    data.append(to_string(ntohs(dns_rd_rrsig->key_tag)).append(" "));
    data.append(read_domain_name(dns_hdr, dns + sizeof(dns_rd_rrsig_t), &shift).append(" "));

    dns += sizeof(dns_rd_rrsig_t) + shift;

    data.append(bin_to_hexa(dns, data_len - (shift + sizeof(dns_rd_rrsig_t))).substr(0, DIGEST_PRINT_LEN).append("..."));

    return data;
}

string DnsParser::parse_record_soa(u_char *dns_hdr, u_char *dns)
{
    string data;
    u_int shift;

    data = read_domain_name(dns_hdr, dns, &shift).append(" ");
    dns += shift;

    data.append(read_domain_name(dns_hdr, dns, &shift).append(" "));
    dns += shift;

    auto *dns_rd_soa = reinterpret_cast<dns_rd_soa_t *>(dns);

    data.append(to_string(ntohl(dns_rd_soa->serial)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->refresh)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->retry)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->expire)).append(" "));
    data.append(to_string(ntohl(dns_rd_soa->minimum)));

    return data;
}

string DnsParser::parse_record_txt_spf(u_char *dns)
{
    string data;
    while (*dns != '\0') {
        data += *dns;
        dns++;
    }
    return data;
}
