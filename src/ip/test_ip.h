#ifndef _test_ip_H_
#define _test_ip_H_

#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "IPProtocol.h"

struct StackEthernetIP
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;

        StackEthernetIP()
        {
                eth = EthernetProtocolPtr(new EthernetProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());

                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

                // configure the ip handler
                ip->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip->setHeaderSize(ip->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip,std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip,std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
	}
	~StackEthernetIP() {
                // nothing to delete
        }
};

struct StackEthernetVLanIP
{
        EthernetProtocolPtr eth;
        VLanProtocolPtr vlan;
        IPProtocolPtr ip;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_vlan;
        MultiplexerPtr mux_ip;

        StackEthernetVLanIP()
        {
                eth = EthernetProtocolPtr(new EthernetProtocol());
                vlan = VLanProtocolPtr(new VLanProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_vlan = MultiplexerPtr(new Multiplexer());

                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

                // configure the vlan handler
                vlan->setMultiplexer(mux_vlan);
                mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan));
		mux_vlan->setProtocolIdentifier(ETH_P_8021Q);
                mux_vlan->setHeaderSize(vlan->getHeaderSize());
                mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan,std::placeholders::_1));
                mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket,vlan,std::placeholders::_1));

                // configure the ip handler
                ip->setMultiplexer(mux_ip);
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
                mux_ip->setHeaderSize(ip->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip,std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip,std::placeholders::_1));

        	// configure the multiplexers
        	mux_eth->addUpMultiplexer(mux_vlan,ETH_P_8021Q);
		mux_vlan->addDownMultiplexer(mux_eth);
		mux_vlan->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_vlan);

        }
        ~StackEthernetVLanIP() {
                // nothing to delete
        }
};

#endif
