#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <csignal>
#include <boost/program_options.hpp>
#include <fstream>
#include "PacketDispatcher.h"
#include "StackLan.h"
#include "Stack3G.h"

PacketDispatcherPtr pktdis;

void signalHandler( int signum )
{
        if(pktdis)
        {
              //pktdis->statistics();
        }
        exit(signum);
}

int main(int argc, char* argv[])
{
	std::string stack_name;
	std::string pcapfile;
	std::string interface;
	bool print_flows = false;
	bool show_statistics = false;
	int tcp_flows_cache;
	int udp_flows_cache;

	namespace po = boost::program_options;

	po::options_description mandatory_ops("Mandatory arguments");
	mandatory_ops.add_options()
//		("interface,i",   po::value<std::string>(&device)->required(),
//			"sets the interface.")
		("pcapfile,f",   po::value<std::string>(&pcapfile)->required(),
			"Sets the pcap file.")
        	;

	po::options_description optional_ops_tcp("TCP optional arguments");
	optional_ops_tcp.add_options()
		("tcp-flows,t",    po::value<int>(&tcp_flows_cache)->default_value(32768),
		  	"Sets the number of TCP flows on the pool.")
		;
	
	po::options_description optional_ops_udp("UDP optional arguments");
	optional_ops_udp.add_options()
		("udp-flows,u",    po::value<int>(&udp_flows_cache)->default_value(16384),
		  	"Sets the number of UDP flows on the pool.")
		;
	mandatory_ops.add(optional_ops_tcp);
	mandatory_ops.add(optional_ops_udp);

	po::options_description optional_ops("Optional arguments");
	optional_ops.add_options()
		("stack,s",	po::value<std::string>(&stack_name)->default_value("lan"),
				      	"Sets the network stack (lan,3g).")
		("dumpflows,d",      	"Dump the flows to stdout.")
		("statistics,S",      	"Show statistics of the stack.")
		("help,h",     		"Show help")
		("version,v",   	"Show version string")
		;

	mandatory_ops.add(optional_ops);

	try
	{
		po::variables_map vm;
        	po::store(po::parse_command_line(argc, argv, mandatory_ops), vm);

        	if (vm.count("help"))
        	{
            		std::cout << "iaengine " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
            		return false;
        	}
        	if (vm.count("version"))
        	{
            		std::cout << "iaengine " VERSION << std::endl;
            		return false;
        	}
		if (vm.count("dumpflows"))
		{
			print_flows = true;
		}
		if (vm.count("statistics"))
		{
			show_statistics = true;
		}

        	po::notify(vm);
    	}
	catch(boost::program_options::required_option& e)
    	{
            	std::cout << "iaengine " VERSION << std::endl;
        	std::cerr << "Error: " << e.what() << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
    	}
    	catch(...)
    	{	
            	std::cout << "iaengine " VERSION << std::endl;
        	std::cerr << "Unsupported option." << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
    	}


    	signal(SIGINT, signalHandler);  

	pktdis = PacketDispatcherPtr(new PacketDispatcher());
	NetworkStackPtr stack;

	if(stack_name.compare("lan") == 0)
	{
		stack = NetworkStackPtr(new StackLan());
	}else{
		if (stack_name.compare("3g") ==0)
		{
			stack = NetworkStackPtr(new Stack3G());
		}else{
			std::cout << "iaengine: Unknown stack " << stack_name << std::endl;
			exit(-1);
		}
	}
	stack->setTotalTCPFlows(tcp_flows_cache);	
	stack->setTotalUDPFlows(udp_flows_cache);	

	// connect with the stack
        pktdis->setDefaultMultiplexer(stack->getLinkLayerMultiplexer().lock());

	std::cout << "Processing pcapfile:" << pcapfile << std::endl;
        pktdis->openPcapFile(pcapfile.c_str());

	try
	{
        	pktdis->run();
        	//pktdis->runPcap();
   	}
   	catch(std::exception& e)
   	{
      		std::cerr << "Error: " << e.what() << std::endl;
	}
        pktdis->closePcapFile();

	if(show_statistics)
	{
		stack->statistics();	
	}

	if(print_flows)
	{
		stack->printFlows();
	}

	return 0;
}

