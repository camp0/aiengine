#include <string>
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "IPProtocol.h"


#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE iptest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (ip_suite) // name of the test suite is stringtest

// check a IP header values
//
BOOST_AUTO_TEST_CASE (test1_ip)
{
	IPProtocol *ip = new IPProtocol();
	std::string localip("192.168.1.25");	
	std::string remoteip("66.220.153.28");	
	char *raw_packet="\x45\x00"
		"\x00\x34\x8b\x1e\x40\x00\x80\x06\xd1\xeb\xc0\xa8\x01\x19\x42\xdc"
		"\x99\x1c\x05\xb1\x00\x50\x06\xa4\x1a\x34\x00\x00\x00\x00\x80\x02"
		"\xff\xff\xaa\x84\x00\x00\x02\x04\x05\xb4\x01\x03\x03\x01\x01\x01"
		"\x04\x02";
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
	int length = 52;

	ip->setIPHeader(packet);
	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(ip->getTTL() == 128);
	BOOST_CHECK(ip->getIPHeaderLength() == 20);
	BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
	BOOST_CHECK(ip->getPacketLength() == length);

	BOOST_CHECK(localip.compare(ip->getSrcAddrDotNotation())==0);
	BOOST_CHECK(remoteip.compare(ip->getDstAddrDotNotation())==0);

	delete ip;	
}

BOOST_AUTO_TEST_CASE (test2_ip) // ethernet -> ip 
{
        EthernetProtocol *eth = new EthernetProtocol();
        MultiplexerPtr mux_eth = MultiplexerPtr(new Multiplexer());
	IPProtocol *ip = new IPProtocol();
        MultiplexerPtr mux_ip = MultiplexerPtr(new Multiplexer());

	// ethernet ->ip ->udp -> dns
	char *raw_packet = "\x00\x0c\x29\x2e\x3c\x2a\x90\x84\x0d\x62\xd8\x04\x08\x00\x45\x00"
		"\x00\x3d\x8a\x0d\x00\x00\xec\x11\xf4\x4f\xc0\xa8\x01\x76\x50\x3a"
		"\x3d\xfa\xe9\xb3\x00\x35\x00\x29\x05\x94\x84\xd3\x01\x00\x00\x01"
		"\x00\x00\x00\x00\x00\x00\x02\x63\x68\x04\x70\x6f\x6f\x6c\x03\x6e"
		"\x74\x70\x03\x6f\x72\x67\x00\x00\x01\x00\x01";
	int length = 75;
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
	
	//configure the eth 
	eth->setMultiplexer(mux_eth);
        mux_eth->setHeaderSize(eth->header_size);
        mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

	// configure the ip
	ip->setMultiplexer(mux_ip);
        mux_ip->setHeaderSize(ip->header_size);
        mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));

	// configure the multiplexers
        mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
        mux_ip->addDownMultiplexer(mux_eth);	

	mux_eth->setPacketInfo(0,packet,length);
	eth->setEthernetHeader(mux_eth->getRawPacket());     
	// Sets the raw packet to a valid ethernet header
        BOOST_CHECK(eth->getEthernetType() == ETH_P_IP);

	// executing the packet
	// forward the packet through the multiplexers
        mux_eth->setPacketInfo(0,packet,length);
        mux_eth->forward();	

        BOOST_CHECK(mux_eth->getPacketLength() == length);
        BOOST_CHECK(mux_ip->getPacketLength() == length - 14);

	delete ip;
	delete eth;
}

BOOST_AUTO_TEST_CASE (test3_ip) // ethernet -> vlan -> ip 
{
        EthernetProtocol *eth = new EthernetProtocol();
        MultiplexerPtr mux_eth = MultiplexerPtr(new Multiplexer());
        VLanProtocol *vlan = new VLanProtocol();
        MultiplexerPtr mux_vlan = MultiplexerPtr(new Multiplexer());
	IPProtocol *ip = new IPProtocol();
        MultiplexerPtr mux_ip = MultiplexerPtr(new Multiplexer());

	// ethernet -> vlan ->ip ->udp -> dns
	char *raw_packet = "\x00\x0c\x29\x2e\x3c\x2a\x90\x84\x0d\x62\xd8\x04" "\x81\x00\x02\x5e\x08\x00"
		"\x45\x00"
		"\x00\x3d\x8a\x0d\x00\x00\xec\x11\xf4\x4f\xc0\xa8\x01\x76\x50\x3a"
		"\x3d\xfa\xe9\xb3\x00\x35\x00\x29\x05\x94\x84\xd3\x01\x00\x00\x01"
		"\x00\x00\x00\x00\x00\x00\x02\x63\x68\x04\x70\x6f\x6f\x6c\x03\x6e"
		"\x74\x70\x03\x6f\x72\x67\x00\x00\x01\x00\x01";
	int length = 79;
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
	
	//configure the eth 
	eth->setMultiplexer(mux_eth);
        mux_eth->setHeaderSize(eth->header_size);
        mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

	//configure the vlan 
	vlan->setMultiplexer(mux_vlan);
        mux_vlan->setHeaderSize(vlan->header_size);
        mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan));

	// configure the ip
	ip->setMultiplexer(mux_ip);
        mux_ip->setHeaderSize(ip->header_size);
        mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));

	// configure the multiplexers
        mux_eth->addUpMultiplexer(mux_vlan,ETH_P_8021Q);
        mux_vlan->addDownMultiplexer(mux_eth);	
        mux_vlan->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
        mux_ip->addDownMultiplexer(mux_vlan);	

	// executing the packet
	// forward the packet through the multiplexers
        mux_eth->setPacketInfo(0,packet,length);
    	eth->setEthernetHeader(mux_eth->getRawPacket()); 
	mux_eth->forward();	

	BOOST_CHECK(vlan->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalPackets() == 1);

        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_vlan->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_eth->getPacketLength() == length);
        BOOST_CHECK(mux_vlan->getPacketLength() == length - 14);
        BOOST_CHECK(mux_ip->getPacketLength() == length - (14 + 4 ));

        BOOST_CHECK(ip->getPacketLength() == mux_ip->getPacketLength());
        BOOST_CHECK(eth->getEthernetType() == ETH_P_8021Q);
        BOOST_CHECK(vlan->getEthernetType() == ETH_P_IP);

	delete ip;
	delete vlan;
	delete eth;
}

// Multiplexers configuration for test4_ip
//
//          ip_mux   
//            \     
//          vlan_mux 
//              \    
//              eth_mux
//

BOOST_AUTO_TEST_CASE (test4_ip) // ethernet -> vlan -> ip
{
        EthernetProtocol *eth = new EthernetProtocol();
        MultiplexerPtr mux_eth = MultiplexerPtr(new Multiplexer());
        VLanProtocol *vlan = new VLanProtocol();
        MultiplexerPtr mux_vlan = MultiplexerPtr(new Multiplexer());
        IPProtocol *ip = new IPProtocol();
        MultiplexerPtr mux_ip = MultiplexerPtr(new Multiplexer());

        // ethernet -> vlan ->ip ->udp -> dns
        char *raw_packet = "\x00\x0c\x29\x2e\x3c\x2a\x90\x84\x0d\x62\xd8\x04" "\x08\x00"
                "\x45\x00"
                "\x00\x3d\x8a\x0d\x00\x00\xec\x11\xf4\x4f\xc0\xa8\x01\x76\x50\x3a"
                "\x3d\xfa\xe9\xb3\x00\x35\x00\x29\x05\x94\x84\xd3\x01\x00\x00\x01"
                "\x00\x00\x00\x00\x00\x00\x02\x63\x68\x04\x70\x6f\x6f\x6c\x03\x6e"
                "\x74\x70\x03\x6f\x72\x67\x00\x00\x01\x00\x01";
        int length = 75;
        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);

        //configure the eth
        eth->setMultiplexer(mux_eth);
        mux_eth->setHeaderSize(eth->header_size);
        mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

        //configure the vlan
        vlan->setMultiplexer(mux_vlan);
        mux_vlan->setHeaderSize(vlan->header_size);
        mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan));

        // configure the ip
        ip->setMultiplexer(mux_ip);
        mux_ip->setHeaderSize(ip->header_size);
        mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));

        // configure the multiplexers
        mux_eth->addUpMultiplexer(mux_vlan,ETH_P_8021Q);
        mux_vlan->addDownMultiplexer(mux_eth);
        mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
        mux_ip->addDownMultiplexer(mux_eth);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacketInfo(0,packet,length);
        eth->setEthernetHeader(mux_eth->getRawPacket());
        mux_eth->forward();
        
	BOOST_CHECK(vlan->getTotalPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 1);

        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 1);

        BOOST_CHECK(mux_eth->getPacketLength() == length);
        BOOST_CHECK(mux_vlan->getPacketLength() == 0);
        BOOST_CHECK(mux_ip->getPacketLength() == length - (14 ));

        BOOST_CHECK(ip->getPacketLength() == mux_ip->getPacketLength());
        BOOST_CHECK(ip->getProtocol() == IPPROTO_UDP);
        BOOST_CHECK(eth->getEthernetType() == ETH_P_IP);

	delete ip;
	delete eth;
	delete vlan;
}

// Multiplexers configuration for test5_ip
//
//                    mux_ip2 
//                     /
//          vlan_mux mux_ip1
//              \    /
//              mux_eth
//

BOOST_AUTO_TEST_CASE (test5_ip) // ethernet -> vlan -> ip
{
        EthernetProtocol *eth = new EthernetProtocol();
        MultiplexerPtr mux_eth = MultiplexerPtr(new Multiplexer());
        VLanProtocol *vlan = new VLanProtocol();
        MultiplexerPtr mux_vlan = MultiplexerPtr(new Multiplexer());
        IPProtocol *ip1 = new IPProtocol();
        MultiplexerPtr mux_ip1 = MultiplexerPtr(new Multiplexer());
        IPProtocol *ip2 = new IPProtocol();
        MultiplexerPtr mux_ip2 = MultiplexerPtr(new Multiplexer());

        // ethernet -> ip ->ip ->udp -> dns
        char *raw_packet = "\x00\x0c\x29\x2e\x3c\x2a\x90\x84\x0d\x62\xd8\x04" "\x08\x00"
		// IP
		"\x45\x00\x00\x51\x00\x00\x40\x00\x40" "\x04" "\xd5\x57\x0a\x3a\x09\x76"
		"\xc3\x72\x8d\xd1"
		// IP
                "\x45\x00" // 36
                "\x00\x3d\x8a\x0d\x00\x00\xec\x11\xf4\x4f\xc0\xa8\x01\x76\x50\x3a" 
                "\x3d\xfa"
		/* udp */
		"\xe9\xb3\x00\x35\x00\x29\x05\x94"
		// dns
		"\x84\xd3\x01\x00\x00\x01"
                "\x00\x00\x00\x00\x00\x00\x02\x63\x68\x04\x70\x6f\x6f\x6c\x03\x6e" // 84
                "\x74\x70\x03\x6f\x72\x67\x00\x00\x01\x00\x01"; // 95 
        int length = 95;
        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);

        //configure the eth
        eth->setMultiplexer(mux_eth);
        mux_eth->setHeaderSize(eth->header_size);
        mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

        //configure the vlan
        vlan->setMultiplexer(mux_vlan);
        mux_vlan->setHeaderSize(vlan->header_size);
        mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan));

        // configure the ip1
        ip1->setMultiplexer(mux_ip1);
        mux_ip1->setHeaderSize(ip1->header_size);
        mux_ip1->addChecker(std::bind(&IPProtocol::ipChecker,ip1));

        // configure the ip2
        ip2->setMultiplexer(mux_ip2);
        mux_ip2->setHeaderSize(ip2->header_size);
        mux_ip2->addChecker(std::bind(&IPProtocol::ipChecker,ip2));

        // configure the multiplexers
        mux_eth->addUpMultiplexer(mux_vlan,ETH_P_8021Q);
        mux_vlan->addDownMultiplexer(mux_eth);
        mux_eth->addUpMultiplexer(mux_ip1,ETHERTYPE_IP);
        mux_ip1->addDownMultiplexer(mux_eth);
	mux_ip1->addUpMultiplexer(mux_ip2,IPPROTO_IPIP);
	mux_ip2->addDownMultiplexer(mux_ip1);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacketInfo(0,packet,length);
        eth->setEthernetHeader(mux_eth->getRawPacket());
        mux_eth->forward();

	// Now check all the path that the packet have take
        BOOST_CHECK(vlan->getTotalPackets() == 0);
        BOOST_CHECK(ip1->getTotalPackets() == 1);
        BOOST_CHECK(ip2->getTotalPackets() == 1);

        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_ip1->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip2->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_ip2->getTotalFailPackets() == 1);

	// check the integrity of the ethernet
        BOOST_CHECK(eth->getEthernetType() == ETH_P_IP);

	// check the integrity of the first ip header
        BOOST_CHECK(ip1->getTTL() == 64);
        BOOST_CHECK(ip1->getIPHeaderLength() == 20);
        BOOST_CHECK(ip1->getProtocol() == IPPROTO_IPIP);
        BOOST_CHECK(ip1->getPacketLength() == length - 14);

        BOOST_CHECK(mux_eth->getPacketLength() == length);
        BOOST_CHECK(mux_vlan->getPacketLength() == 0);
        BOOST_CHECK(mux_ip1->getPacketLength() == length - (14 ));
        BOOST_CHECK(mux_ip2->getPacketLength() == length - (14 + 20));

        BOOST_CHECK(ip1->getPacketLength() == mux_ip1->getPacketLength());
        BOOST_CHECK(ip2->getPacketLength() == mux_ip2->getPacketLength());

        BOOST_CHECK(ip1->getProtocol() == IPPROTO_IPIP);
        BOOST_CHECK(ip2->getProtocol() == IPPROTO_UDP);

	// check integrity of the second ip header
	std::string src_ip("192.168.1.118");
	std::string dst_ip("80.58.61.250");

        BOOST_CHECK(src_ip.compare(ip2->getSrcAddrDotNotation())==0);
        BOOST_CHECK(dst_ip.compare(ip2->getDstAddrDotNotation())==0);

	delete ip1;
	delete ip2;
	delete vlan;
	delete eth;
}


BOOST_AUTO_TEST_SUITE_END( )

