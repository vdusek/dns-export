// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.cpp

#include <string>
#include <iostream>
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
    std::cout << "parsuju " << this->filename << endl;
}