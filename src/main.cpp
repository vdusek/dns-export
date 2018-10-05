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

int main(int argc, char *argv[])
{
    ArgParser arg_parser;
    try {
        arg_parser.parse(argc, argv);
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

    if (arg_parser.get_resource() != "") {
        PcapParser pcap_parser(arg_parser.get_resource());
        pcap_parser.parse();
    }

    // ToDo:

    return 0;
}
