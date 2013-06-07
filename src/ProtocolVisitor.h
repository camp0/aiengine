#ifndef _ProtocolVisitor_H_
#define _ProtocolVisitor_H_

#include <boost/variant.hpp>
#include <fstream>

class EthernetProtocol;
class VLanProtocol;

typedef boost::variant<EthernetProtocol,VLanProtocol,int> variantProtocol;
//typedef variantProtocol::VariantType variantProtocolType;

class ProtocolVisitor 
{
public:
	void operator()(EthernetProtocol &eth) {};
	void operator()(int &eth) {};
	void operator()(VLanProtocol &vlan) {};
/*	void operator()(IPProtocol &ip) {};
	void operator()(ICMPProtocol &icmp) {};
	void operator()(UDPProtocol &udp) {};
	void operator()(TCPProtocol &tcp) {};
*/
};

#endif
