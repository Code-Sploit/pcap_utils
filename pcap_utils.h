#include <iostream>
#include <vector>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"


/**
* A struct for collecting packet statistics
*/
struct PacketStats
{
    int ethPacketCount;
    int ipv4PacketCount;
    int ipv6PacketCount;
    int tcpPacketCount;
    int udpPacketCount;
    int dnsPacketCount;
    int httpPacketCount;
    int sslPacketCount;

    std::vector<pcpp::Packet> packetVector;

    /**
    * Clear all stats
    */
    void clear() { ethPacketCount = 0; ipv4PacketCount = 0; ipv6PacketCount = 0; tcpPacketCount = 0; udpPacketCount = 0; tcpPacketCount = 0; dnsPacketCount = 0; httpPacketCount = 0; sslPacketCount = 0; }

    /**
    * C'tor
    */
    PacketStats() { clear(); }

    /**
    * Collect stats from a packet
    */
    void consumePacket(pcpp::Packet& packet)
    {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
    }

    void addPacket(pcpp::Packet& packet)
    {
        packetVector.push_back(packet);
    }

    /**
    * Print stats to console
    */
    void printToConsole()
    {
        std::cout
            << "Ethernet packet count: " << ethPacketCount << std::endl
            << "IPv4 packet count:     " << ipv4PacketCount << std::endl
            << "IPv6 packet count:     " << ipv6PacketCount << std::endl
            << "TCP packet count:      " << tcpPacketCount << std::endl
            << "UDP packet count:      " << udpPacketCount << std::endl
            << "DNS packet count:      " << dnsPacketCount << std::endl
            << "HTTP packet count:     " << httpPacketCount << std::endl
            << "SSL packet count:      " << sslPacketCount << std::endl;
    }
};

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType) {
    switch(protocolType) {
        case pcpp::Ethernet:
            return "Ethernet";

        case pcpp::IPv4:
            return "IPv4";

        case pcpp::TCP:
            return "TCP";

        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
            return "HTTP";

        default:
            return "Unknown";
    }
}

std::string printTcpFlags(pcpp::TcpLayer* tcpLayer)
{
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";

    return result;
}

std::string printTcpOptionType(pcpp::TcpOptionType optionType)
{
    switch (optionType)
    {
    case pcpp::PCPP_TCPOPT_NOP:
        return "NOP";
    case pcpp::PCPP_TCPOPT_TIMESTAMP:
        return "Timestamp";
    default:
        return "Other";
    }
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
    switch (httpMethod)
    {
    case pcpp::HttpRequestLayer::HttpGET:
        return "GET";
    case pcpp::HttpRequestLayer::HttpPOST:
        return "POST";
    default:
        return "Other";
    }
}

std::string getPacketType(pcpp::Packet& packet) {
    if (packet.isPacketOfType(pcpp::Ethernet))
        return "ETH";

    if (packet.isPacketOfType(pcpp::IPv4))
        return "IPV4";

    if (packet.isPacketOfType(pcpp::IPv6))
        return "IPV6";

    if (packet.isPacketOfType(pcpp::TCP))
        return "TCP";

    if (packet.isPacketOfType(pcpp::UDP))
        return "UDP";

    if (packet.isPacketOfType(pcpp::DNS))
        return "DNS";

    if (packet.isPacketOfType(pcpp::HTTP))
        return "HTTP";

    if (packet.isPacketOfType(pcpp::SSL))
        return "SSL";

    return "Unknown";
}

class parsePackets {
    public:
        int parsePacketIPv4(pcpp::Packet parsedPacket) {
            pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

            if (ipLayer == NULL) {
                std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;

                return 1;
            }

            // print source and dest IP addresses, IP ID and TTL
            std::cout << std::endl
                << "[IP4]: Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
                << "[IP4]: Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
                << "[IP4]: IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
                << "[IP4]: TTL: " << std::dec << (int)ipLayer->getIPv4Header()->timeToLive << std::endl;

            return 0;
        }

        int parsePacketEth(pcpp::Packet parsedPacket) {
            pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

            if (ethernetLayer == NULL) {
                std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;

                return 1;
            }

            // print source and dest MAC addresses and the Ether type
            std::cout << std::endl
                << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
                << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
                << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

            return 0;
        }

        int parsePacketTCP(pcpp::Packet parsedPacket) {
            pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

            if (tcpLayer == NULL)
            {
                std::cerr << "Something went wrong, couldn't find TCP layer" << std::endl;

                return 1;
            }

            // print TCP source and dest ports, window size, and the TCP flags that are set in this layer
            std::cout << std::endl
                << "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
                << "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
                << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl
                << "TCP flags: " << printTcpFlags(tcpLayer) << std::endl;

                // go over all TCP options in this layer and print its type
                std::cout << "TCP options: ";

                for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
                {
                    std::cout << printTcpOptionType(tcpOption.getTcpOptionType()) << " ";
                }

                std::cout << std::endl;

            return 0;
        }

        int parsePacketHttp(pcpp::Packet parsedPacket) {
            pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();

            if (httpRequestLayer == NULL)
            {
                std::cerr << "Something went wrong, couldn't find HTTP request layer" << std::endl;

                return 1;
            }

            std::cout << std::endl
                << "HTTP method: " << printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()) << std::endl
                << "HTTP URI: " << httpRequestLayer->getFirstLine()->getUri() << std::endl;

                // print values of the following HTTP field: Host, User-Agent and Cookie
            std::cout
                << "HTTP host: " << httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() << std::endl
                << "HTTP user-agent: " << httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue() << std::endl
                << "HTTP cookie: " << httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue() << std::endl;

                // print the full URL of this request
            std::cout << "HTTP full URL: " << httpRequestLayer->getUrl() << std::endl;

            return 0;
        }
};
