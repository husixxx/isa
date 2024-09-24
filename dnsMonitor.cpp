#include "dnsMonitor.hpp"

void dnsMonitor::startSniffing(helper::Config &config)
{
    pcap_t *handle = nullptr;

    std::string interface = config.interface;
    if (config.interface != "")
    {

        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr)
        {
            cerr << "Could not open device " << interface << ": " << errbuf << endl;
            exit(1);
        }
    }
    else if (config.pcapFile != "")
    {

        handle = pcap_open_offline(config.pcapFile.c_str(), errbuf);
    }

    string filter = "udp port 53";

    if (config.verbose)
    {
        this->verbose = true;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "Could not parse filter " << filter << ": " << pcap_geterr(handle) << endl;
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        cerr << "Could not install filter " << filter << ": " << pcap_geterr(handle) << endl;
        exit(1);
    }

    pcap_freecode(&fp); // free

    pcap_loop(handle, 0, printPacket, reinterpret_cast<u_char *>(this));
}

void dnsMonitor::printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    dnsMonitor *monitor = reinterpret_cast<dnsMonitor *>(args);

    time_t timer = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timer);
    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
    char tzbuffer[6];
    strftime(tzbuffer, sizeof(buffer), "%z", timeinfo);
   
    string timestamp = string(buffer);

    cout << "timestamp: " << timestamp << endl;
    struct ether_header *eth = (struct ether_header *)packet;

    switch (ntohs(eth->ether_type))
    {
    case ETHERTYPE_IP:
        monitor->printIpv4(packet);
        break;
    case ETHERTYPE_IPV6:
        monitor->printIpv6(packet);
        break;
    }
}

void dnsMonitor::printIpv4(const u_char *packet)
{

    struct ip *ipheader = (struct ip *)(packet + sizeof(struct ether_header));

    if (this->verbose)
    {
        cout << "SrcIP: " << inet_ntoa(ipheader->ip_src) << endl;
        cout << "DstIp: " << inet_ntoa(ipheader->ip_dst) << endl;
        this->printPorts(packet + ipheader->ip_hl * 4);
    }
    else
    {
        cout << inet_ntoa(ipheader->ip_src) << " -> " << inet_ntoa(ipheader->ip_dst) << endl;
    }
    // // Načítanie DNS hlavičky
    // struct dnshdr *dnsHeader = (struct dnshdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
}

void dnsMonitor::printIpv6(const u_char *packet)
{
    char ip6_addr[INET6_ADDRSTRLEN];
    struct ip6_hdr *ip6header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    if (this->verbose)
    {

        cout << "src IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_src), ip6_addr, INET6_ADDRSTRLEN) << endl;
        cout << "dst IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_dst), ip6_addr, INET6_ADDRSTRLEN) << endl;
        this->printPorts(packet + sizeof(struct ip6_hdr));
    }
    else
    {
        cout << inet_ntop(AF_INET6, &(ip6header->ip6_src), ip6_addr, INET6_ADDRSTRLEN) << " -> " << inet_ntop(AF_INET6, &(ip6header->ip6_dst), ip6_addr, INET6_ADDRSTRLEN) << endl;
    }
}

void dnsMonitor::printPorts(const u_char *packet)
{
    const struct ip *ipheader = (const struct ip *)packet;

    const struct udphdr *udpheader = (struct udphdr *)(packet + sizeof(ether_header) + ipheader->ip_hl * 4);

    int srcPort = ntohs(udpheader->source);
    int dstPort = ntohs(udpheader->dest);
    cout << "UDP/" << srcPort << endl;
    cout << "UDP/" << dstPort << endl;

    this->printDetails(packet + sizeof(ether_header) + ipheader->ip_hl * 4 + sizeof(struct udphdr));
}

void dnsMonitor::printDetails(const u_char *packet)
{

    uint16_t id = ntohs(*(uint16_t *)packet);
    cout << "Identifier: 0x" << hex << setw(4) << setfill('0') << id << dec << endl;

    uint16_t flags = ntohs(*(uint16_t *)(packet + 2));

    uint8_t qr = (flags & 0x8000) >> 15;

    uint8_t opcode = (flags & 0x7800) >> 11;

    uint8_t aa = (flags & 0x0400) >> 10;

    uint8_t tc = (flags & 0x0200) >> 9;

    uint8_t rd = (flags & 0x0100) >> 8;

    uint8_t ra = (flags & 0x0080) >> 7;

    uint8_t ad = (flags & 0x0020) >> 5;

    uint8_t cd = (flags & 0x0010) >> 4;

    uint8_t rcode = (flags & 0x000F);

    cout << "Flags: "
         << "QR=" << static_cast<int>(qr) << ", "
         << "OPCODE=" << static_cast<int>(opcode) << ", "
         << "AA=" << static_cast<int>(aa) << ", "
         << "TC=" << static_cast<int>(tc) << ", "
         << "RD=" << static_cast<int>(rd) << ", "
         << "RA=" << static_cast<int>(ra) << ", "
         << "AD=" << static_cast<int>(ad) << ", "
         << "CD=" << static_cast<int>(cd) << ", "
         << "RCODE=" << static_cast<int>(rcode) << endl;

    // uint16_t qdcount = ntohs(*(uint16_t *)(packet + 4));
    // cout << "DNS QDCOUNT (Number of Questions): " << qdcount << endl;


    // uint16_t ancount = ntohs(*(uint16_t *)(packet + 6));
    // cout << "DNS ANCOUNT (Number of Answer RRs): " << ancount << endl;

    // uint16_t nscount = ntohs(*(uint16_t *)(packet + 8));
    // cout << "DNS NSCOUNT (Number of Authority RRs): " << nscount << endl;

    // uint16_t arcount = ntohs(*(uint16_t *)(packet + 10));
    // cout << "DNS ARCOUNT (Number of Additional RRs): " << arcount << endl;

    cout << "[Question Section]" << endl;

    string domainName = this->printDomainName(packet, 12);

    // TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    uint16_t type = ntohs(*(uint16_t *)(packet + 12 + domainName.length() + 2));
    
    string recordType = this->getRecordType(type);
    uint16_t classType = ntohs(*(uint16_t *)(packet + 12 + domainName.length() + 4));
    
    string recordClass = this->getRecordClass(classType);

    cout << domainName << " " << recordClass << " " << recordType << endl;



}

string dnsMonitor::printDomainName(const u_char *packet, int offset)
{
    string domainName = "";
    int length = packet[offset];
    while (length != 0)
    {
        if ((length & 0xC0) == 0xC0)
        {
            int pointer = ((length & 0x3F) << 8) + packet[offset + 1];
            printDomainName(packet, pointer);
            offset += 2;
            break;
        }
        for (int i = 0; i < length; i++)
        {
            domainName += packet[offset + i + 1];
        }
        domainName += ".";
        offset += length + 1;
        length = packet[offset];
    }
    domainName.pop_back();
    return domainName;
}


string dnsMonitor::getRecordType(uint16_t type)
{
    switch(type){
        case 0x0001:
            return "A";
        case 0x0002:
            return "NS";
        case 0x0005:
            return "CNAME";
        case 0x0006:
            return "SOA";
        case 0x000f:
            return "MX";
        case 0x001c:
            return "AAAA";
        case 0x0021:
            return "SRV";
        default:
            return "Unknown";
    }
}

string dnsMonitor::getRecordClass(uint16_t type)
{
    switch(type){
        case 0x0001:
            return "IN";
        case 0x0002:
            return "CS";
        case 0x0003:
            return "CH";
        case 0x0004:
            return "HS";
        default:
            return "Unknown";
    }
}