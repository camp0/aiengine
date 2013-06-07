#ifndef _ProtocolVisitor_H_
#define _ProtocolVisitor_H_

#include <boost/variant.hpp>
#include <fstream>
//#include "./ethernet/EthernetProtocol.h"

class EthernetProtocol;

typedef boost::variant<EthernetProtocol,int> variantProtocolTypes;

class ProtocolVisitor 
{
public:
	void operator()(EthernetProtocol &eth) {};
	void operator()(int &eth) {};
/*	void operator()(VLanProtocol &vlan) {};
	void operator()(IPProtocol &ip) {};
	void operator()(ICMPProtocol &icmp) {};
	void operator()(UDPProtocol &udp) {};
	void operator()(TCPProtocol &tcp) {};
*/
};

#endif
