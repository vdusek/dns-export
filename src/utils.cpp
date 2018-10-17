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

#include "pcap_parser.h"
#include "utils.h"

using namespace std;

unordered_map<string, int> result_map;

void print_help()
{
    cout << HELP_TEXT << endl;
}

void error(RetCode ret_code, string message)
{
    cerr << message << endl;
    exit(ret_code);
}

void signal_handler(int sig)
{
    if (sig == SIGALRM) {
        pcap_breakloop(handle);
    }
    else if (sig == SIGUSR1) {
        for (const auto &elem : result_map) {
            cout << elem.first << elem.second << endl;
        }
    }
}

u_int8_t reverse_bits(u_int8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}

string bin_to_time(u_int32_t time)
{
    auto raw_time = static_cast<time_t>(time);
    struct tm *timeinfo = localtime(&raw_time);
    char *buffer = (char*) malloc(200);
    const char *format = "%Y-%m-%d %H:%M:%S";
    strftime(buffer, 200, format, timeinfo);

//    if (strftime(buffer, 200, format, timeinfo) == 0) {
//        fprintf(stderr, "strftime returned 0");
//        exit(EXIT_FAILURE);
//    }

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
        name += '.';

        if (!ptr) {
            (*shift)++;
        }
    }

    if (!name.empty()) {
        name.pop_back();
        name += '\0';
    }

    if (ptr) {
        (*shift) += 2;
    }
    else {
        (*shift)++;
    }

    return name;
}


ArgumentException::ArgumentException(const std::string &message) : std::invalid_argument(message) {}

HelpException::HelpException() = default;

//PcapException::PcapException(const std::string &msg) : m_msg(msg) {}

