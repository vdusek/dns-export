// VUT FIT 3BIT
// ISA 2018/2019
// Project: Programovani sitove sluzby
// Variant: 2 - Export DNS informaci pomoci protokolu Syslog
// Author: Vladimir Dusek, xdusek27
// Date: 30/9/2018
// File: pcap_parser.h

#pragma once

#include <string>
#include <pcap/pcap.h>

class PcapParser {
private:
    std::string m_filename;

public:
    /**
     * Constructor.
     */
    PcapParser(std::string filename);

    /**
     * Destructor.
     */
    ~PcapParser();

    /**
     * Parse pcap file.
     */
    void parse();
};
