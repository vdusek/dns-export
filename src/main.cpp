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
#include "syslog.h"

using namespace std;

int main(int argc, char **argv)
{
    // Parse command line arguments
    ArgParser arg_parser(argc, argv);
    try {
        arg_parser.parse();
    }
    catch (ArgumentException &exc) {
        error(RET_ARGS_ERR, string(exc.what()));
    }
    catch (HelpException &exc) {
        print_help();
        return 0;
    }

    // Debug print
    arg_parser.print();

    // Parse pcap file or sniff on network interface
    PcapParser pcap_parser(FILTER);
    try {
        if (!arg_parser.resource().empty()) {
            pcap_parser.parse_file(arg_parser.resource());
        }
        else if (!arg_parser.interface().empty()) {
            pcap_parser.parse_interface(arg_parser.interface(), arg_parser.timeout());
        }
    }
    catch (PcapException &exc) {
        error(RET_PCAP_ERR, string(exc.what()));
    }
    catch (SystemException &exc) {
        error(RET_SYS_ERR, string(exc.what()));
    }

    cout << endl;

//    for (pair<string, int> elem: result_map) {
//        cout << elem.first << elem.second << endl;
//    }

    // ToDo: destructor is not called after catched exception
    Syslog syslog(arg_parser.server());
    try {
        syslog.connect();
        for (pair<string, int> elem: result_map) {
            syslog.send_log(elem.first + to_string(elem.second));
        }
        syslog.disconnect();
    }
    catch (SyslogException &exc) {
        cout << "exc catched" << endl;
        error(RET_SYSLOG_ERR, string(exc.what()));
    }

    return 0;
}
