#include "Stack3G.h"

Stack3G::Stack3G()
{
	// Allocate all the Protocol objects
        tcp_ = TCPProtocolPtr(new TCPProtocol());
        udp_ = UDPProtocolPtr(new UDPProtocol());
        ip_ = IPProtocolPtr(new IPProtocol());
        eth_ = EthernetProtocolPtr(new EthernetProtocol());
        icmp_ = ICMPProtocolPtr(new ICMPProtocol());
        http_ = HTTPProtocolPtr(new HTTPProtocol());
        ssl_ = SSLProtocolPtr(new SSLProtocol());

	// Allocate the Multiplexers
	mux_eth_ = MultiplexerPtr(new Multiplexer());
	mux_ip_ = MultiplexerPtr(new Multiplexer());
	mux_udp_ = MultiplexerPtr(new Multiplexer());
	mux_tcp_ = MultiplexerPtr(new Multiplexer());
	mux_icmp_ = MultiplexerPtr(new Multiplexer());

	// Allocate the flow caches and tables
	flow_table_udp_ = FlowManagerPtr(new FlowManager());
	flow_table_tcp_ = FlowManagerPtr(new FlowManager());
	flow_cache_udp_ = FlowCachePtr(new FlowCache());
	flow_cache_tcp_ = FlowCachePtr(new FlowCache());

	ff_tcp_ = FlowForwarderPtr(new FlowForwarder());
	ff_udp_ = FlowForwarderPtr(new FlowForwarder());
	ff_http_ = FlowForwarderPtr(new FlowForwarder());
	ff_ssl_ = FlowForwarderPtr(new FlowForwarder());

	//configure the Ethernet Layer 
	eth_->setMultiplexer(mux_eth_);
	mux_eth_->setProtocol(static_cast<ProtocolPtr>(eth_));
	mux_eth_->setProtocolIdentifier(0);
	mux_eth_->setHeaderSize(eth_->getHeaderSize());
	mux_eth_->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth_,std::placeholders::_1));

	// configure the IP Layer 
	ip_->setMultiplexer(mux_ip_);
	mux_ip_->setProtocol(static_cast<ProtocolPtr>(ip_));
	mux_ip_->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip_->setHeaderSize(ip_->getHeaderSize());
	mux_ip_->addChecker(std::bind(&IPProtocol::ipChecker,ip_,std::placeholders::_1));
	mux_ip_->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_,std::placeholders::_1));

	//configure the ICMP Layer 
	icmp_->setMultiplexer(mux_icmp_);
	mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp_));
	mux_icmp_->setProtocolIdentifier(IPPROTO_ICMP);
	mux_icmp_->setHeaderSize(icmp_->getHeaderSize());
	mux_icmp_->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp_,std::placeholders::_1));

	//configure the UDP Layer 
	udp_->setMultiplexer(mux_udp_);
	mux_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
	ff_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
	mux_udp_->setProtocolIdentifier(IPPROTO_UDP);
	mux_udp_->setHeaderSize(udp_->getHeaderSize());
	mux_udp_->addChecker(std::bind(&UDPProtocol::udpChecker,udp_,std::placeholders::_1));
	mux_udp_->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_,std::placeholders::_1));

	//configure the TCP Layer
	tcp_->setMultiplexer(mux_tcp_);
	mux_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	ff_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	mux_tcp_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_->setHeaderSize(tcp_->getHeaderSize());
	mux_tcp_->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp_,std::placeholders::_1));
	mux_tcp_->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp_,std::placeholders::_1));

	// configure the HTTP Layer 
	http_->setFlowForwarder(ff_http_);
	ff_http_->setProtocol(static_cast<ProtocolPtr>(http_));
	ff_http_->addChecker(std::bind(&HTTPProtocol::httpChecker,http_,std::placeholders::_1));
	ff_http_->addFlowFunction(std::bind(&HTTPProtocol::processFlow,http_,std::placeholders::_1));
	
	// configure the SSL Layer 
	ssl_->setFlowForwarder(ff_ssl_);
	ff_ssl_->setProtocol(static_cast<ProtocolPtr>(ssl_));
	ff_ssl_->addChecker(std::bind(&SSLProtocol::sslChecker,ssl_,std::placeholders::_1));
	ff_ssl_->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl_,std::placeholders::_1));

	// configure the multiplexers
	mux_eth_->addUpMultiplexer(mux_ip_,ETHERTYPE_IP);
	mux_ip_->addDownMultiplexer(mux_eth_);
	mux_ip_->addUpMultiplexer(mux_udp_,IPPROTO_UDP);
	mux_udp_->addDownMultiplexer(mux_ip_);
	mux_ip_->addUpMultiplexer(mux_tcp_,IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip_);
	mux_ip_->addUpMultiplexer(mux_icmp_,IPPROTO_ICMP);
	mux_icmp_->addDownMultiplexer(mux_ip_);
	
	// Connect the FlowManager and FlowCache
	tcp_->setFlowCache(flow_cache_tcp_);
	tcp_->setFlowManager(flow_table_tcp_);
			
	udp_->setFlowCache(flow_cache_udp_);
	udp_->setFlowManager(flow_table_udp_);
	
	// Configure the FlowForwarders
	tcp_->setFlowForwarder(ff_tcp_);	
	udp_->setFlowForwarder(ff_udp_);	
	
	ff_tcp_->addUpFlowForwarder(ff_http_);
	ff_tcp_->addUpFlowForwarder(ff_ssl_);

}

void Stack3G::statistics(std::basic_ostream<char>& out)
{
	
	eth_->statistics(out);
	out << std::endl;
	ip_->statistics(out);
	out << std::endl;
	tcp_->statistics(out);
	out << std::endl;
	udp_->statistics(out);
	out << std::endl;
	icmp_->statistics(out);
	out << std::endl;
	http_->statistics(out);
	out << std::endl;
	ssl_->statistics(out);
}

void Stack3G::printFlows(std::basic_ostream<char>& out)
{
	out << "Flows on memory" << std::endl;
	flow_table_tcp_->printFlows(out);
	flow_table_udp_->printFlows(out);
}


