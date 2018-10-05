// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <string>
#include <iostream>
#include <pcap/pcap.h>
#include "pcap_parser.h"

using namespace std;

PcapParser::PcapParser(std::string filename)
{
    this->filename = filename;
}

PcapParser::~PcapParser()
{
}

void PcapParser::parse()
{
    cout << "parsuju " << this->filename << endl;
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t *tmp = nullptr;
    tmp = pcap_open_offline(this->filename.c_str(), error_buffer);

    // ToDo
}
