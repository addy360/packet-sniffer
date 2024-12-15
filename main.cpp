#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void handler(u_char *userData, const struct pcap_pkthdr *packetHeader, const u_char *packet);
void printDevice(pcap_if_t *dev);
void handleTcp(struct ip *ipHeader, const u_char *packet);
void handleUdp(struct ip *ipHeader, const u_char *packet);

int main()
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs, *dev;

    if (pcap_findalldevs(&devs, errorBuffer))
    {
        std::cerr << "Failed to get all devices " << errorBuffer << std::endl;
        return -1;
    }

    int foundDevs = 0;

    for (dev = devs; dev != nullptr; dev = dev->next)
    {
        printDevice(dev);
        foundDevs++;
    }

    if (foundDevs == 0)
    {
        std::cerr << "No device detected, exiting...\n";
        return -1;
    }

    std::cout << "Found [" << foundDevs << "] devices\n";
    std::cout << "---------------------\n";

    dev = devs;

    std::cout << "Using ";
    printDevice(dev);

    pcap_t *hndlr = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errorBuffer);

    if (hndlr == nullptr)
    {
        std::cerr << "We failed to capture device" << errorBuffer << std::endl;
        return -1;
    }

    std::cout << "Starting packet capture ..." << std::endl;

    pcap_loop(hndlr, 10, handler, nullptr);

    return 0;
}

void printDevice(pcap_if_t *dev)
{
    std::cout << dev->name << " - " << (dev->description ? " - " : "") << (dev->description ? dev->description : "") << std::endl;
}

void handler(u_char *userData, const struct pcap_pkthdr *packetHeader, const u_char *packet)
{
    struct ip *ipHeader = (struct ip *)(packet + 14);
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);
    std::string ips =
        "Source: " + std::string(srcIp) +
        "\tDestination: " + std::string(dstIp) +
        "\n";

    std::cout << ips;

    switch (ipHeader->ip_p)
    {
    case IPPROTO_TCP:
        handleTcp(ipHeader, packet);
        break;
    case IPPROTO_UDP:
        handleUdp(ipHeader, packet);
        break;
    default:
        std::cout << "Other\t:\t" << ipHeader->ip_p << std::endl;
        break;
    }
}

void handleTcp(struct ip *ipHeader, const u_char *packet)
{
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4);
    std::cout << "Protocol : TCP, Source Port : " << ntohs(tcpHeader->th_sport) << "\tDestination Port : " << ntohs(tcpHeader->th_dport) << std::endl;
    std::cout << "+++++++++++++++++++++++++++++++\n\n";
}

void handleUdp(struct ip *ipHeader, const u_char *packet)
{
    struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + ipHeader->ip_hl * 4);
    std::cout << "Protocol : UDP, Source Port : " << ntohs(udpHeader->uh_sport) << "\tDestination Port : " << ntohs(udpHeader->uh_dport) << std::endl;
    std::cout << "+++++++++++++++++++++++++++++++\n\n";
}
