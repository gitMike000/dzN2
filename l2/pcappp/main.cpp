#include <iostream>
#include <chrono>
#include <thread>

#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"

struct PacketStat
{
    int ethPackCnt;
    int ipv4PackCnt;
    int ipv6PackCnt;
    int tcpPackCnt;
    int udpPackCnt;
    int dnsPackCnt;
    int httpPackCnt;
    int sslPackCnt;


    void clr() { ethPackCnt = 0; ipv4PackCnt = 0; ipv6PackCnt = 0; tcpPackCnt = 0; udpPackCnt = 0; tcpPackCnt = 0; dnsPackCnt = 0; httpPackCnt = 0; sslPackCnt = 0; }

    PacketStat() { clr(); }

	void consumePacket(pcpp::Packet& packet)
	{
		if (packet.isPacketOfType(pcpp::Ethernet))
            ethPackCnt++;
		if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PackCnt++;
		if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PackCnt++;
		if (packet.isPacketOfType(pcpp::TCP))
            tcpPackCnt++;
		if (packet.isPacketOfType(pcpp::UDP))
            udpPackCnt++;
		if (packet.isPacketOfType(pcpp::HTTP))
            httpPackCnt++;
		if (packet.isPacketOfType(pcpp::SSL))
            sslPackCnt++;
	}

    void ToConsole()
	{
                std::cout << "Ethernet packet count: " << ethPackCnt << std::endl;
                std::cout << "IPv4 packet count:     " << ipv4PackCnt << std::endl;
                std::cout << "IPv6 packet count:     " << ipv6PackCnt << std::endl;
                std::cout << "TCP packet count:      " << tcpPackCnt << std::endl;
                std::cout << "UDP packet count:      " << udpPackCnt << std::endl;
                std::cout << "DNS packet count:      " << dnsPackCnt << std::endl;
                std::cout << "HTTP packet count:     " << httpPackCnt << std::endl;
                std::cout << "SSL packet count:      " << sslPackCnt << std::endl;
	}
};

int main(int argc, char* argv[])
{
        if (argc != 4)
        {
            std::cerr << "Usage: " << argv[0] << " <interface-ip or ip> <capture-file> <time(second) 1..20>" << std::endl;
            return EXIT_FAILURE;
        }

        std::string cap_filename=argv[2];
        cap_filename += ".pcap";

        int cap_time=std::stoi(argv[3]);
        if (cap_time<1 || cap_time>20)
        {
            std::cout << "Capture time out of range" << std::endl;;
            exit(1);
        }

        // IPv4 address of the interface we want to sniff
        std::string interfaceIPAddr = argv[1];

        // find the interface by IP address or name
        pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceIPAddr.c_str());
	if (dev == NULL)
	{
                std::cout << "Cannot find interface with IPv4 address of " << interfaceIPAddr.c_str() << std::endl;;
		exit(1);
	}

        pcpp::PcapFileWriterDevice* writer = new pcpp::PcapFileWriterDevice(cap_filename);
        if (!writer->open())
        {
            std::cout << "Can't open file" << cap_filename << std::endl;
            exit(1);
        }


        std::cout << "Interface info:\n"<<std::endl;
        std::cout << "   Interface name:     "<< dev->getName()<<std::endl;
        std::cout << "   Interface description: "<< dev->getDesc()<<std::endl;
        std::cout << "   MAC address:           " << dev->getMacAddress().toString().c_str()<<std::endl;
        std::cout << "   Default gateway:       " << dev->getDefaultGateway().toString().c_str()<<std::endl;
        std::cout << "   Interface MTU:         " << dev->getMtu() <<std::endl;

	if (dev->getDnsServers().size() > 0)
                std::cout << "   DNS server:            " << dev->getDnsServers().at(0).toString().c_str() <<std::endl;

        // promise mode
        pcpp::PcapLiveDevice::DeviceConfiguration devConfig(pcpp::PcapLiveDevice::Promiscuous,pcpp::PcapLiveDevice::PCPP_INOUT);

        if (!dev->open(devConfig))
        {
            std::cout << "Cannot open device\n" <<std::endl;
            exit(1);
        }

	// create the stats object
    PacketStat stats;


    std::cout << "\nStarting capture with packet vector...\n";
    std::cout << "Waiting " << cap_time <<" seconds"<<std::endl;

	pcpp::RawPacketVector packetVec;

	dev->startCapture(packetVec);

    std::chrono::seconds timespan(cap_time);
    std::this_thread::sleep_for(timespan);

    dev->stopCapture();

    writer->writePackets(packetVec);
    writer->flush();
    std::cout << std::endl << "Capture file created " << std::endl;

	for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{

		pcpp::Packet parsedPacket(*iter);

		stats.consumePacket(parsedPacket);
	}

	printf("Results:\n");
    stats.ToConsole();

    stats.clr();
    writer->close();
	dev->close();
}
