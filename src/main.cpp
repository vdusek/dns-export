// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: main.cpp

#include <iostream>
#include <string>
#include "utils.h"
#include "arg_parser.h"
#include "pcap_parser.h"

using namespace std;

int main(int argc, char **argv)
{
    ArgParser arg_parser(argc, argv);
    try {
        arg_parser.parse();
    }
    catch (ArgumentException &exc) {
        error(RET_INV_ARGS, "dns-export: " + string(exc.what()));
    }

    // Debug
    arg_parser.print();

    if (arg_parser.get_help()) {
        print_help();
        return 0;
    }

    PcapParser pcap_parser(arg_parser.get_resource(), arg_parser.get_interface());

    if (arg_parser.get_resource() != "") {
        pcap_parser.parse_file();
    }
    else if (arg_parser.get_interface() != "") {
        pcap_parser.parse_interface(arg_parser.get_timeout());
    }

    return 0;
}
