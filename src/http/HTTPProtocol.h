#ifndef _HTTPProtocol_H_
#define _HTTPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../FlowForwarder.h"
#include "../Protocol.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <boost/regex.hpp>

class HTTPProtocol: public Protocol 
{
public:
    	explicit HTTPProtocol():http_header_(nullptr),total_bytes_(0),
		http_regex_("^(GET|POST|HEAD|PUT|TRACE).*HTTP/1.")
	{ 
		name_="HTTPProtocol";
	}
    	virtual ~HTTPProtocol() {};
	
	static const u_int16_t id = 0;
	static const int header_size = 0;
	int getHeaderSize() const { return header_size;};

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        const char *getName() { return name_.c_str();};

	void processPacket();
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setFlowForwarder(FlowForwarderPtrWeak ff) { flow_forwarder_= ff; };
        FlowForwarderPtrWeak getFlowForwarder() { return flow_forwarder_;};

        void setHeader(unsigned char *raw_packet)
        {
                http_header_ = reinterpret_cast <unsigned char*> (raw_packet);
        }


        // Condition for say that a payload is HTTp 
        bool httpChecker(unsigned char *payload)
        {
		const char * paco = reinterpret_cast<const char*>(payload);

		std::cout << "httpChecker:" << std::endl;
		if(boost::regex_search(paco, what_, http_regex_)) 
                {
                        std::cout << "http valid packet" << std::endl;
                        ++total_valid_packets_;
                        return true;
                }
                else
                {
                        ++total_malformed_packets_;
                        return false;
                }
        }

private:
	FlowForwarderPtrWeak flow_forwarder_;
	boost::regex http_regex_;
        boost::cmatch what_;
	MultiplexerPtrWeak mux_;
	unsigned char *http_header_;
	int32_t total_bytes_;
};

typedef std::shared_ptr<HTTPProtocol> HTTPProtocolPtr;

#endif
