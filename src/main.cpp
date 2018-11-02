// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: main.cpp

// ToDo:
// - Better parse base64 field in NSSEC
//     - source: https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp

#include <unistd.h>
#include <vector>
#include "utils.h"
#include "arg_parser.h"
#include "pcap_parser.h"
#include "syslog.h"

using namespace std;

// Global instance of Syslog because of signal_handler
Syslog syslog;

// Global instance of ArgParser because of signal_handler
ArgParser arg_parser;

// Global instance of PcapParser because of signal_handler
PcapParser pcap_parser(FILTER_EXP);

// Connect to syslog if not connected and send data from result_map to syslog server.
void send_stats_to_syslog()
{
    try {
        pcap_parser.parse_tcp();
        if (!syslog.connected()) {
            syslog.connect();
        }
        for (auto &elem: result_map) {
            syslog.send_log(elem.first + to_string(elem.second));
        }
    }
    catch (SyslogException &exc) {
        cerr << PROJ_NAME << ": " << string(exc.what()) << flush;
        exit(RET_SYSLOG_ERR);
    }
    catch (SystemException &exc) {
        cerr << PROJ_NAME << ": " << string(exc.what()) << flush;
        exit(RET_SYS_ERR);
    }
}

// Print data from result_map on stdout.
void print_stats_on_stdout()
{
    try {
        pcap_parser.parse_tcp();
        for (auto &elem: result_map) {
            cout << elem.first << elem.second << endl;
        }
    }
    catch (SystemException &exc) {
        cerr << PROJ_NAME << ": " << string(exc.what()) << flush;
        exit(RET_SYS_ERR);
    }
}

// Signal handler
void signal_handler(int signal)
{
    switch (signal) {
        case SIGALRM:
            alarm(arg_parser.get_timeout());
            send_stats_to_syslog();
            break;

        case SIGUSR1:
            print_stats_on_stdout();
            break;

        case SIGINT:
            pcap_breakloop(handle);
            send_stats_to_syslog();
            syslog.disconnect();
            DEBUG_PRINT("\n");
            DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
            DEBUG_PRINT("Summary:\n");
            DEBUG_PRINT("    Number of captured frames = " + to_string(frame_cnt) + "\n");
            DEBUG_PRINT("    Number of IPv4 datagrams = " + to_string(ipv4_cnt) + "\n");
            DEBUG_PRINT("    Number of IPv6 datagrams = " + to_string(ipv6_cnt) + "\n");
            DEBUG_PRINT("    Number of other datagrams = " + to_string(not_ipv4_ipv6_cnt) + "\n");
            DEBUG_PRINT("    Number of UDP packets = " + to_string(udp_cnt) + "\n");
            DEBUG_PRINT("    Number of TCP packets = " + to_string(tcp_cnt) + "\n");
            DEBUG_PRINT("    Number of correct DNS responses = " + to_string(dns_cnt) + "\n");
            DEBUG_PRINT("    Number of DNS answers = " + to_string(dns_ans_cnt) + "\n\n");
            DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
            exit(0);

        default:
            break;
    }
}

// Main
int main(int argc, char **argv)
{
    // Parse command line arguments
    arg_parser.set_args(argc, argv);
    try {
        arg_parser.parse();
    }
    catch (ArgumentException &exc) {
        cerr << PROJ_NAME << ": " << string(exc.what()) << flush;
        return RET_ARGS_ERR;
    }
    catch (HelpException &exc) {
        cout << HELP_TEXT << flush;
        return EXIT_SUCCESS;
    }

    // Set address of syslog server
    syslog.set_server_address(arg_parser.get_server());

    arg_parser.debug_print(); // debug

    // Set signal handler
    if ((signal(SIGINT,  signal_handler) == SIG_ERR) ||
        (signal(SIGUSR1, signal_handler) == SIG_ERR) ||
        (signal(SIGALRM, signal_handler) == SIG_ERR))
    {
        cerr << PROJ_NAME << ": Unable to set signal handler\n" << flush;
        return RET_SYS_ERR;
    }

    // Parse pcap file or sniff on network interface
    try {
        if (!arg_parser.get_resource().empty()) {
            pcap_parser.set_resource(arg_parser.get_resource());
            pcap_parser.parse_resource();
        }
        else if (!arg_parser.get_interface().empty()) {
            // Set alarm
            alarm(arg_parser.get_timeout());
            pcap_parser.set_interface(arg_parser.get_interface());
            pcap_parser.sniff_interface();
        }
    }
    catch (PcapException &exc) {
        cerr << PROJ_NAME << ": " << string(exc.what()) << flush;
        return RET_PCAP_ERR;
    }
    catch (SystemException &exc) {
        cerr << PROJ_NAME << ": " << string(exc.what()) << flush;
        return RET_SYS_ERR;
    }

    // In case of parsing file, send statistics to syslog
    if (!arg_parser.get_resource().empty()) {
        send_stats_to_syslog();
        syslog.disconnect();
    }

    DEBUG_PRINT("------------------------------------------------------------------------------\n\n");
    DEBUG_PRINT("Summary:\n");
    DEBUG_PRINT("    Number of captured frames = " + to_string(frame_cnt) + "\n");
    DEBUG_PRINT("    Number of IPv4 datagrams = " + to_string(ipv4_cnt) + "\n");
    DEBUG_PRINT("    Number of IPv6 datagrams = " + to_string(ipv6_cnt) + "\n");
    DEBUG_PRINT("    Number of other datagrams = " + to_string(not_ipv4_ipv6_cnt) + "\n");
    DEBUG_PRINT("    Number of UDP packets = " + to_string(udp_cnt) + "\n");
    DEBUG_PRINT("    Number of TCP packets = " + to_string(tcp_cnt) + "\n");
    DEBUG_PRINT("    Number of correct DNS responses = " + to_string(dns_cnt) + "\n");
    DEBUG_PRINT("    Number of DNS answers = " + to_string(dns_ans_cnt) + "\n");
    DEBUG_PRINT("\n------------------------------------------------------------------------------\n\n");

    return EXIT_SUCCESS;
}

