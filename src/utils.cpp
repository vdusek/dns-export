// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: error.cpp

#include <signal.h>

#include <iostream>
#include <string>
#include <sstream>
#include <syslog.h>

#include "pcap_parser.h"
#include "utils.h"

using namespace std;

unordered_map<string, int> result_map;

u_char reverse_bits(u_char byte) {
    byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;
    byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
    byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
    return byte;
}

string bin_to_time(u_int32_t time)
{
    char buffer[BUFFER_SIZE] = {0};
    auto raw_time = static_cast<time_t>(time);
    tm *ts = gmtime(&raw_time);

    if (strftime(buffer, BUFFER_SIZE, "%Y-%m-%dT%H:%M:%SZ", ts) == 0) {
        throw SystemException("strftime failure\n");
    }

    return string(buffer);
}

string bin_to_hexa(u_char *data, u_int count)
{
    stringstream ss;

    for (u_int32_t i = 0; i < count; i++) {
        ss << hex << static_cast<u_int16_t>(data[i]);
    }

    return ss.str();
}

string read_domain_name(u_char *dns_hdr, u_char *dns, u_int *shift)
{
    string name;
    u_int32_t offset;
    bool ptr = false;
    *shift = 0;

    while (*dns != '\0') {
        /* "The significance of the compression label is as follows: the first 2 bits are set to 1,
         * the 14 remaining bits describe the offset, i.e. the position of the compression target
         * from the beginning of the DNS message." */
        if (*dns >= 0b11000000) {
            offset = (u_int32_t) ((*dns) * 0x100 + *(dns + 1) - 0xC000); // calculation of offset
            dns = dns_hdr + offset;
            ptr = true;
        }
        for (int cnt = *dns; cnt > 0; cnt--) {
            dns++;
            name += *dns;

            if (!ptr) {
                (*shift)++;
            }
        }
        dns++;
        name.append(".");
        if (!ptr) {
            (*shift)++;
        }
    }

    if (!name.empty()) {
        name.pop_back();
    }
    if (ptr) {
        (*shift) += 2;
    }
    else {
        (*shift)++;
    }

    return name;
}

ArgumentException::ArgumentException(const string &message): invalid_argument(message) {}

HelpException::HelpException() = default;

PcapException::PcapException(const string &message): runtime_error(message) {}

SyslogException::SyslogException(const string &message): runtime_error(message) {}

SystemException::SystemException(const string &message): runtime_error(message) {}
