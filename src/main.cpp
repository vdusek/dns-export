// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: main.cpp

#include <iostream>
#include <unordered_map>

#include "utils.h"
#include "arg_parser.h"
#include "pcap_parser.h"

using namespace std;

int main(int argc, char **argv)
{
    // Parse command line arguments
    ArgParser arg_parser(argc, argv);
    try {
        arg_parser.parse();
    }
    catch (ArgumentException &exc) {
        error(RET_INV_ARGS, "dns-export: " + string(exc.what()));
    }
    catch (HelpException &exc) {
        print_help();
        return 0;
    }

    // Debug print
    arg_parser.print();

    // Parse pcap file or sniff on network interface
    PcapParser pcap_parser;
    if (!arg_parser.resource().empty()) {
        pcap_parser.parse_file(arg_parser.resource());
    }
    else if (!arg_parser.interface().empty()) {
        pcap_parser.parse_interface(arg_parser.interface(), arg_parser.timeout());
    }

    // Send statistics to syslog
    // ToDo: not print, but send to syslog
    for (const auto &elem : result_map) {
        cout << elem.first << elem.second << endl;
    }

    return 0;
}
