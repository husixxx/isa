#include "dnsMonitor.hpp"
using namespace std;

void dnsMonitor::startSniffing(helper::Config &config)
{
    pcap_t *handle = nullptr;

    if (config.domainsFile != "")
    {
        this->file = fopen(config.domainsFile.c_str(), "w");
        domainCheck = true;
    }
    else
    {
        domainCheck = false;
    }

    string interface = config.interface;
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
    else
    {
        this->verbose = false;
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
    // fclose(file);
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

    if (monitor->verbose)
    {
        cout << "Timestamp: " << timestamp << endl;
    }
    else
    {
        cout << timestamp << " ";
    }
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
        this->printIp4Ports(packet + ipheader->ip_hl * 4);
    }
    else
    {
        cout << inet_ntoa(ipheader->ip_src) << " -> " << inet_ntoa(ipheader->ip_dst);
        this->printIp4Ports(packet + ipheader->ip_hl * 4);
    }
}

void dnsMonitor::printIpv6(const u_char *packet)
{
    char ip6_addr[INET6_ADDRSTRLEN];
    struct ip6_hdr *ip6header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    if (this->verbose)
    {

        cout << "src IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_src), ip6_addr, INET6_ADDRSTRLEN) << endl;
        cout << "dst IP: " << inet_ntop(AF_INET6, &(ip6header->ip6_dst), ip6_addr, INET6_ADDRSTRLEN) << endl;

        this->printIp6Ports(packet + sizeof(struct ip6_hdr));
    }
    else
    {
        cout << inet_ntop(AF_INET6, &(ip6header->ip6_src), ip6_addr, INET6_ADDRSTRLEN) << " -> " << inet_ntop(AF_INET6, &(ip6header->ip6_dst), ip6_addr, INET6_ADDRSTRLEN);
        this->printIp6Ports(packet + sizeof(struct ip6_hdr));
    }
}

void dnsMonitor::printIp6Ports(const u_char *packet)
{

    const struct udphdr *udpheader = (struct udphdr *)(packet + sizeof(ether_header));

    int srcPort = ntohs(udpheader->source);
    int dstPort = ntohs(udpheader->dest);

    if (verbose)
    {

        cout << "UDP/" << dstPort << endl;
        cout << "UDP/" << srcPort << endl;
    }

    this->printDetails(packet + sizeof(ether_header) + sizeof(struct udphdr));
}

void dnsMonitor::printDetails(const u_char *packet)
{

    int offset = 2;
    uint16_t id = ntohs(*(uint16_t *)packet);
    if (this->verbose)
    {

        cout << "Identifier: 0x" << hex << setw(4) << setfill('0') << id << dec << endl;
    }

    uint16_t flags = ntohs(*(uint16_t *)(packet + offset));
    offset += 2;

    uint8_t qr = (flags & 0x8000) >> 15;
    uint8_t opcode = (flags & 0x7800) >> 11;
    uint8_t aa = (flags & 0x0400) >> 10;
    uint8_t tc = (flags & 0x0200) >> 9;
    uint8_t rd = (flags & 0x0100) >> 8;
    uint8_t ra = (flags & 0x0080) >> 7;
    uint8_t ad = (flags & 0x0020) >> 5;
    uint8_t cd = (flags & 0x0010) >> 4;
    uint8_t rcode = (flags & 0x000F);

    if (this->verbose)
    {
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
    }

    // uint16_t qdcount = ntohs(*(uint16_t *)(packet + 4));
    // cout << "DNS QDCOUNT (Number of Questions): " << qdcount << endl;

    int numberOfQuestions = static_cast<int>(ntohs(*(uint16_t *)(packet + offset)));
    offset += 2;
    int numberOfAnswers = static_cast<int>(ntohs(*(uint16_t *)(packet + offset)));
    offset += 2;
    int numberOfAuthority = static_cast<int>(ntohs(*(uint16_t *)(packet + offset)));
    offset += 2;
    int numberOfAdditional = static_cast<int>(ntohs(*(uint16_t *)(packet + offset)));
    offset += 2;

    string qrBit = qr == 1 ? "R" : "Q";

    if (!this->verbose && !domainCheck)
    {
        cout << "(" << qrBit << " " << numberOfQuestions << "/" << numberOfAnswers << "/" << numberOfAuthority << "/" << numberOfAdditional << ")" << endl;
        return;
    }

    this->printQuestionSection(packet, offset, numberOfQuestions);
    if (numberOfAnswers != 0)
        this->printAnswerSection(packet, offset, numberOfAnswers);
    if (numberOfAuthority != 0)
        this->printAuthoritySection(packet, offset, numberOfAuthority);
    if (numberOfAdditional != 0)
        this->printAdditionalSection(packet, offset, numberOfAdditional);

    cout << "====================" << endl;
}

pair<string, int> dnsMonitor::printDomainName(const u_char *packet, int offset)
{
    string domainName = "";
    int length = packet[offset];
    int originalOffset = offset;
    while (length != 0)
    {
        // compression
        if ((length & 0xC0) == 0xC0)
        {
            // calculate the pointer
            int pointer = ((length & 0x3F) << 8) + packet[offset + 1];
            // call to decode at the pointing location
            domainName += printDomainName(packet, pointer).first;
            offset += 2; // move
            // if (domainCheck)
            // {

            //     if (find(domains.begin(), domains.end(), domainName) == domains.end())
            //     {
            //         domains.push_back(domainName);
            //         fprintf(file, "%s\n", domainName.c_str());
            //     }
            // }

            return {domainName, offset};
        }
        for (int i = 0; i < length; i++)
        {
            domainName += packet[offset + i + 1];
        }
        domainName += ".";

        // move
        offset += length + 1;
        length = packet[offset];
    }

    if (!domainName.empty() && domainName.back() == '.')
    {
        domainName.pop_back();
    }

    // mov
    // if (this->domains.find(domainName) == this->domains.end())
    // {
    //     this->domains.insert(domainName);
    //     cout << "KKT";
    // fprintf(file, "%s\n", domainName.c_str());
    // }
    return {domainName, offset + 1};
}

void dnsMonitor::printAuthoritySection(const u_char *packet, int &offset, int count)
{
    while (count > 0)
    {
        // 2 for authority section
        offset = this->printRecord(packet, offset, 2);
        count--;
    }
}

void dnsMonitor::printAnswerSection(const u_char *packet, int &offset, int count)
{
    
    while (count > 0)
    {
        offset = this->printRecord(packet, offset, 1);
        count--;
    }
}

void dnsMonitor::printQuestionSection(const u_char *packet, int &offset, int count)
{
    
    while (count > 0)
    {
        auto domain = printDomainName(packet, offset);
        loadDomains(domain.first);
        string domainName = domain.first;
        offset = domain.second;
        uint16_t type = ntohs(*(uint16_t *)(packet + offset));
        offset += 2;
        string recordType = this->getRecordType(type);
        uint16_t classType = ntohs(*(uint16_t *)(packet + offset));
        offset += 2;
        string recordClass = this->getRecordClass(classType);
        if(recordType == "Unknown" || recordClass == "Unknown")
        {
            count--;
            continue;
        }
        if (verbose){
            cout << endl << "[Question Section]" << endl;
            cout << domainName << " " << recordClass << " " << recordType << endl;
        }
    
        count--;
    }
}


void dnsMonitor::loadDomains(string domainName)
{
    if (domainCheck)
    {
        if (find(domains.begin(), domains.end(), domainName) == domains.end())
        {
            domains.push_back(domainName);
            fprintf(file, "%s\n", domainName.c_str());
            fflush(file);
        }
    }
}


void dnsMonitor::printAdditionalSection(const u_char *packet, int &offset, int count)
{
    
    while (count > 0)
    {
        // 3 for additional section
        offset = this->printRecord(packet, offset, 3);
        count--;
    }
}

int dnsMonitor::printRecord(const u_char *packet, int offset, int type)
{
    // Name 2 bytes
    auto domain = this->printDomainName(packet, offset);
    loadDomains(domain.first);
    string additionalDomainName = domain.first;
    offset = domain.second;
    // Type 2 bytes
    uint16_t additionalType = ntohs(*(uint16_t *)(packet + offset));
    string additionalRecordType = this->getRecordType(additionalType);
    // Class 2 bytes
    uint16_t additionalClassType = ntohs(*(uint16_t *)(packet + offset + 2));
    string additionalRecordClass = this->getRecordClass(additionalClassType);
    // TTL 4 bytes
    uint32_t ttl = ntohl(*(uint32_t *)(packet + offset + 4));
    // Data Length 2 bytes
    uint16_t dataLength = ntohs(*(uint16_t *)(packet + offset + 8));
    // ==
    // Rdata
    // 10 bytes
    offset += 10;
    string rdata = printRdata(packet, offset, additionalType, dataLength);
    if(additionalRecordType == "Unknown" || additionalRecordClass == "Unknown" || rdata == "Unknown type"){
            return offset;
        }
    if (verbose)
    {
        if(type == 2){
            cout << endl << "[Authority Section]" << endl;
        }else if(type == 3){
            cout << endl << "[Additional Section]" << endl;
        }else if(type == 1){
            cout << endl << "[Answer Section]" << endl;
        }
        cout << additionalDomainName << " " << ttl << " " << additionalRecordClass << " " << additionalRecordType << " " << rdata << endl;
    }
    return offset;
}

void dnsMonitor::printIp4Ports(const u_char *packet)
{

    const struct udphdr *udpheader = (struct udphdr *)(packet + sizeof(ether_header));

    int srcPort = ntohs(udpheader->source);
    int dstPort = ntohs(udpheader->dest);

    if (this->verbose)
    {
        cout << "UDP/" << srcPort << endl;
        cout << "UDP/" << dstPort << endl;
    }

    this->printDetails(packet + sizeof(ether_header) + sizeof(struct udphdr));
}

string dnsMonitor::printRdata(const u_char *packet, int &offset, int type, int length)
{

    string rdata = "";

    switch (type)
    {
    case 1: // A record (IPv4 address)
    {
        // IPv4 adresa je vždy 4 bajty, prevedieme ju na čitateľný formát
        char ipv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, packet + offset, ipv4, INET_ADDRSTRLEN);
        rdata = ipv4;
        offset += 4;
        break;
    }
    case 28: // AAAA record (IPv6 address)
    {
        // IPv6 adresa je vždy 16 bajtov, prevedieme ju na čitateľný formát
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, packet + offset, ipv6, INET6_ADDRSTRLEN);
        rdata = ipv6;
        offset += 16;
        break;
    }
    case 5: // CNAME record
    {
        // CNAME obsahuje doménové meno (môže byť komprimované)
        auto result = printDomainName(packet, offset);
        loadDomains(result.first);
        rdata = result.first;
        offset = result.second;
        break;
    }
    case 15: // MX record
    {
        // MX obsahuje 2 bajty pre prioritu a potom doménové meno
        int preference = (packet[offset] << 8) | packet[offset + 1];
        auto result = printDomainName(packet, offset + 2); // Doménové meno začína po 2 bajtoch
        loadDomains(result.first);
        rdata = "Preference: " + std::to_string(preference) + ", Mail Exchanger: " + result.first;
        offset = result.second;
        break;
    }
    case 2: // NS record
    {
        // NS obsahuje doménové meno (môže byť komprimované)
        auto result = printDomainName(packet, offset);
        rdata = result.first;
        loadDomains(rdata);
        offset = result.second;
        break;
    }
    case 6: // SOA record (Start of Authority)
    {
        // SOA obsahuje viacero polí: Primary NS, Admin MB, Serial, Refresh, Retry, Expire, Minimum TTL
        auto primaryNs = printDomainName(packet, offset);         // Primárny name server
        loadDomains(primaryNs.first);
        auto adminMb = printDomainName(packet, primaryNs.second); // Email administrátora
        loadDomains(adminMb.first);

        // Následné polia sú celé čísla (4 bajty každé)
        int serial = ntohl(*(int *)(packet + adminMb.second));
        int refresh = ntohl(*(int *)(packet + adminMb.second + 4));
        int retry = ntohl(*(int *)(packet + adminMb.second + 8));
        int expire = ntohl(*(int *)(packet + adminMb.second + 12));
        int minimum = ntohl(*(int *)(packet + adminMb.second + 16));

        rdata = "Primary NS: " + primaryNs.first + ", Admin MB: " + adminMb.first + ", Serial: " + std::to_string(serial) + ", Refresh: " + std::to_string(refresh) + ", Retry: " + std::to_string(retry) + ", Expire: " + std::to_string(expire) + ", Minimum TTL: " + std::to_string(minimum);
        offset = adminMb.second + 20;
        break;
    }
    default:
        rdata = "Unknown type";
        offset += length;
        break;
    }

    return rdata;
}

string dnsMonitor::getRecordType(uint16_t type)
{
    switch (type)
    {
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
    switch (type)
    {
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