#include <iostream>
#include <chrono>
#include <thread>

#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"



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
		if (packet.isPacketOfType(pcpp::HTTP))
			httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL))
			sslPacketCount++;
	}

	/**
	 * Print stats to console
	 */
	void printToConsole()
	{
                std::cout << "Ethernet packet count: " << ethPacketCount << std::endl;
                std::cout << "IPv4 packet count:     " << ipv4PacketCount << std::endl;
                std::cout << "IPv6 packet count:     " << ipv6PacketCount << std::endl;
                std::cout << "TCP packet count:      " << tcpPacketCount << std::endl;
                std::cout << "UDP packet count:      " << udpPacketCount << std::endl;
                std::cout << "DNS packet count:      " << dnsPacketCount << std::endl;
                std::cout << "HTTP packet count:     " << httpPacketCount << std::endl;
                std::cout << "SSL packet count:      " << sslPacketCount << std::endl;
	}
};

/**
 * main method of the application
 */
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

	// Get device info
	// ~~~~~~~~~~~~~~~

        // before capturing packets let's print some info about this interface
        std::cout << "Interface info:\n"<<std::endl;
	// get interface name      
        std::cout << "   Interface name:     "<< dev->getName()<<std::endl;
	// get interface description
        std::cout << "   Interface description: "<< dev->getDesc()<<std::endl;
	// get interface MAC address
        std::cout << "   MAC address:           " << dev->getMacAddress().toString().c_str()<<std::endl;
        // get default gateway for interface
        std::cout << "   Default gateway:       " << dev->getDefaultGateway().toString().c_str()<<std::endl;
        // get interface MTU
        std::cout << "   Interface MTU:         " << dev->getMtu() <<std::endl;
	// get DNS server if defined for this interface
	if (dev->getDnsServers().size() > 0)
                std::cout << "   DNS server:            " << dev->getDnsServers().at(0).toString().c_str() <<std::endl;

        // configurate device promise mode and capture traffics both incoming and outgoing
        pcpp::PcapLiveDevice::DeviceConfiguration devConfig(pcpp::PcapLiveDevice::Promiscuous,pcpp::PcapLiveDevice::PCPP_INOUT);
        // open the device before start capturing/sending packets
        if (!dev->open(devConfig))
	{
                std::cout << "Cannot open device\n" <<std::endl;
		exit(1);
	}

	// create the stats object
	PacketStats stats;


        // Capturing packets in a packet vector
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        std::cout<<"\nStarting capture with packet vector...\n";
        std::cout<<"Waiting " << cap_time <<" seconds"<<std::endl;

	// create an empty packet vector object
	pcpp::RawPacketVector packetVec;

	// start capturing packets. All packets will be added to the packet vector
	dev->startCapture(packetVec);

        // waiting
        std::chrono::seconds timespan(cap_time);
        std::this_thread::sleep_for(timespan);

	// stop capturing packets
        dev->stopCapture();

        // write capture packerts to disk
        writer->writePackets(packetVec);
        writer->flush();
        std::cout << std::endl << "Capture file created " << std::endl;

	// go over the packet vector and feed all packets to the stats object
	for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{
		// parse raw packet
		pcpp::Packet parsedPacket(*iter);

		// feed packet to the stats object
		stats.consumePacket(parsedPacket);
	}

	// print results
	printf("Results:\n");
	stats.printToConsole();

	// clear stats
	stats.clear();

        // close the device and capture file before application ends
        writer->close();
	dev->close();
}
