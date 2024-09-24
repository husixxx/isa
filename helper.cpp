#include "helper.hpp"
using namespace std;



void helper::parseArgs(int argc, char *argv[], Config &config)
{
    bool interface = false;
    bool pcapFile = false;
    for (int i = 1; i < argc; i++)
    {
        if (string(argv[i]) == "-i")
        {

            if (i + 1 >= argc)
            {
                cerr << "Invalid arguments, -i <interface>" << endl;
                exit(1);
            }
            else
            {
                i++;
                config.interface = string(argv[i]);
                interface = true;
            }
        }
        else if (string(argv[i]) == "-r")
        {
            if (i + 1 >= argc)
            {
                cerr << "Invalid arguments, -i <interface>" << endl;
                exit(1);
            }
            else
            {
                i++;
                config.pcapFile = string(argv[i]);
                pcapFile = true;
            }
        }
        else if (string(argv[i]) == "-v")
        {
            config.verbose = true;
        }
        else if (string(argv[i]) == "-d")
        {
            if (i + 1 >= argc)
            {
                cerr << "Invalid arguments, -d <domainsFile>" << endl;
                exit(1);
            }
            else
            {
                i++;
                config.domainsFile = string(argv[i]);
            }
        }else if (string(argv[i]) == "-t")
        {
            if (i + 1 >= argc)
            {
                cerr << "Invalid arguments, -t <translationFile>" << endl;
                exit(1);
            }
            else
            {
                i++;
                config.translationFile = string(argv[i]);
            }
        }
    }

    if((!interface && !pcapFile) || (interface && pcapFile)){
        cerr << "Invalid arguments, -i <interface> or -r <pcapFile>" << endl;
        exit(1);
    }
}