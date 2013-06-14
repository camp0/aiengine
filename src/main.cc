#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <csignal>
#include <boost/program_options.hpp>
#include <fstream>
#include "PacketDispatcher.h"
#include "StackLan.h"


PacketDispatcherPtr pktdis;

bool process_command_line(int argc, char **argv,
	std::string &pcapfile,
	std::string &device)
{
	namespace po = boost::program_options;

	po::options_description mandatory_ops("Mandatory arguments");
	mandatory_ops.add_options()
//		("interface,i",   po::value<std::string>(&device)->required(),
//			"sets the interface.")
		("pcapfile,f",   po::value<std::string>(&pcapfile)->required(),
			"sets the pcap file.")
        	;

	po::options_description optional_ops("Optional arguments");
	optional_ops.add_options()
		("help",     	"show help")
		("version,v",   "show version string")
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


	return true;
}

void signalHandler( int signum )
{
	if(pktdis)
	{
	//	pktdis->statistics();
	}
	exit(signum);  
}

int main(int argc, char* argv[])
{
	std::string pcapfile;
	std::string interface;

	if(!process_command_line(argc,argv,pcapfile,pcapfile))
	{
		return 1;
	}

    	signal(SIGINT, signalHandler);  

	pktdis = PacketDispatcherPtr(new PacketDispatcher());
	StackLan stack = StackLan();
	
	// connect with the stack
        pktdis->setDefaultMultiplexer(stack.mux_eth);

	std::cout << "Processing pcapfile:" << pcapfile << std::endl;
        pktdis->openPcapFile(pcapfile.c_str());

	try
	{
        	pktdis->runPcap();
   	}
   	catch(std::exception& e)
   	{
      		std::cerr << "Error: " << e.what() << std::endl;
	}
	stack.statistics();	
        pktdis->closePcapFile();

	return 0;
}

