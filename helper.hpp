#ifndef helperhpp
#define helperhpp
#include "signal.h"
#include <string>
#include <iostream>
using namespace std;

class helper
{
public:
    struct Config
    {

        string interface;
        string pcapFile;
        bool verbose;
        string domainsFile;
        string translationFile;
    };
    static string createFilter(string config);
    static void parseArgs(int argc, char *argv[], Config &config);
    static void signalHandler(int signum);
    
};

#endif