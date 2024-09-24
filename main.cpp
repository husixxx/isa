#include "dnsMonitor.hpp"



int main(int argc, char *argv[]){


    helper::Config config;

    helper::parseArgs(argc, argv, config);

    dnsMonitor monitor;

    monitor.startSniffing(config);




    return 0;
}