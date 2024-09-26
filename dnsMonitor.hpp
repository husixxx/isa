#ifndef dnsmonitorhpp
#define dnsmonitorhpp
#include "helper.hpp"
#include <arpa/inet.h>
#include <iomanip>
#include <utility>
#include <set>
#include <cstdio>  // Pre FILE*, fopen, fclose
#include <sstream>
#include <ctime>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> // pro ICMP hlavičky
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <pcap.h>
#include <vector>
#include <algorithm>
#include <unordered_map>
using namespace std;
class dnsMonitor
{

    

    public:


    unordered_map<uint16_t, string> recordTypes = {
        {0x0001, "A"},
        {0x0002, "NS"},
        {0x0005, "CNAME"},
        {0x0006, "SOA"},
        {0x000f, "MX"},
        {0x001c, "AAAA"},
        {0x0021, "SRV"},
    };

    unordered_map<uint16_t, string> recordClasses = {
        {0x0001, "IN"},
        {0x0002, "CS"},
        {0x0003, "CH"},
        {0x0004, "HS"},
        
    };



    string getRecordType(uint16_t type);
    string getRecordClass(uint16_t type);       
    void startSniffing(helper::Config &config);                
    void startPcapFile(helper::Config &config);
    void printIpv4(const u_char *packet);
    void printIpv6(const u_char *packet);
    void printIp4Ports(const u_char *packet);
    void printDetails(const u_char *packet);
    pair<string, int> printDomainName(const u_char *packet, int offset);
    void printAnswerSection(const u_char *packet, int& offset, int count);
    void printQuestionSection(const u_char *packet, int& offset, int count);
    void printAuthoritySection(const u_char *packet, int& offset, int count);
    void printAdditionalSection(const u_char *packet, int& offset, int count);
    int printRecord(const u_char *packet, int offset);
    void printIp6Ports(const u_char *packet);
    string printRdata(const u_char *packet, int &offset, int type, int length);
    static void printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
    vector<string> domains;
    void loadDomains(string domainName);
    private:
    char errbuf[PCAP_ERRBUF_SIZE];
    bool verbose;
    bool domainCheck;
    FILE* file;
};



#endif