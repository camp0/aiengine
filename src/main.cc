/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <csignal>
#include <boost/program_options.hpp>
#include <fstream>
#include <boost/variant.hpp>
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"
#include "PacketDispatcher.h"
#include "./frequency/FrequencyGroup.h"
#include "System.h"
#include "StackLan.h"
#include "StackMobile.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

SystemPtr system_stats;
PacketDispatcherPtr pktdis;
NetworkStackPtr stack;
SignatureManagerPtr sm;

std::string stack_name;
std::string pcapfile;
std::string interface;
std::string freqs_group_value;
std::string freqs_type_flows;
bool print_flows = false;
bool enable_frequencies = false;
bool show_statistics = false;
bool show_pstatistics = false;
int tcp_flows_cache;
int udp_flows_cache;

void signalHandler( int signum )
{
        exit(signum);
}

void showFrequencyResults()
{
	FlowManagerPtr flow_t;

	if(freqs_type_flows.compare("tcp")==0) flow_t = stack->getTCPFlowManager().lock();
	if(freqs_type_flows.compare("udp")==0) flow_t = stack->getUDPFlowManager().lock();

	if(!flow_t)
		return;

	FrequencyGroup<std::string> group;

	if(freqs_group_value.compare("src-port") == 0)
        {
        	group.setName("by source port");
		std::cout << "Agregating frequencies " << group.getName() << std::endl;
		group.agregateFlowsBySourcePort(flow_t);
		std::cout << "Computing frequencies " << group.getName() << std::endl;
		group.compute();
		std::cout << group;
	}
	if(freqs_group_value.compare("dst-port") == 0)
        {
        	group.setName("by destination port");
		std::cout << "Agregating frequencies " << group.getName() << std::endl;
		group.agregateFlowsByDestinationPort(flow_t);
		std::cout << "Computing frequencies " << group.getName() << std::endl;
		group.compute();
		std::cout << group;
	}
	if(freqs_group_value.compare("src-ip") == 0)
        {
        	group.setName("by source IP");
		std::cout << "Agregating frequencies " << group.getName() << std::endl;
		group.agregateFlowsBySourceAddress(flow_t);
		std::cout << "Computing frequencies " << group.getName() << std::endl;
		group.compute();
		std::cout << group;
	}
	if(freqs_group_value.compare("dst-ip") == 0)
        {
        	group.setName("by destination IP");
		std::cout << "Agregating frequencies " << group.getName() << std::endl;
		group.agregateFlowsByDestinationAddress(flow_t);
		std::cout << "Computing frequencies " << group.getName() << std::endl;
		group.compute();
		std::cout << group;
	}
        if(freqs_group_value.compare("src-ip,src-port") == 0)
        {
                group.setName("by source IP and port");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsBySourceAddressAndPort(flow_t);
                std::cout << "Computing frequencies " << group.getName() << std::endl;
                group.compute();
                std::cout << group;
        }
        if(freqs_group_value.compare("dst-ip,dst-port") == 0)
        {
                group.setName("by destination IP and port");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsByDestinationAddressAndPort(flow_t);
                std::cout << "Computing frequencies " << group.getName() << std::endl;
                group.compute();
                std::cout << group;
        }

}

void iaengineExit()
{
	if(stack)
	{
		if(show_statistics)
			stack->statistics();
		
		if(print_flows)
              		stack->printFlows();

		if(enable_frequencies)
			showFrequencyResults();

		if(show_pstatistics)	
			if(system_stats)	
				system_stats->statistics();
       	}
}


int main(int argc, char* argv[])
{
	namespace po = boost::program_options;
	po::variables_map var_map;

	po::options_description mandatory_ops("Mandatory arguments");
	mandatory_ops.add_options()
		("interface,i",   po::value<std::string>(&interface),
			"Sets the network interface.")
		("pcapfile,f",   po::value<std::string>(&pcapfile),
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

        po::options_description optional_ops_freq("Frequencies optional arguments");
        optional_ops_freq.add_options()
                ("enable-frequencies,F",  	"Enables the Frequency engine.") 
                ("group-by,g",  	po::value<std::string>(&freqs_group_value)->default_value("dst-port"),
					"Groups frequencies by src-ip,dst-ip,src-port and dst-port.") 
                ("flow-type,T",  	po::value<std::string>(&freqs_type_flows)->default_value("tcp"),
					"Uses tcp or udp flows.") 
                ;

	mandatory_ops.add(optional_ops_tcp);
	mandatory_ops.add(optional_ops_udp);
	mandatory_ops.add(optional_ops_freq);

	po::options_description optional_ops("Optional arguments");
	optional_ops.add_options()
		("stack,s",	po::value<std::string>(&stack_name)->default_value("lan"),
				      	"Sets the network stack (lan,mobile).")
		("dumpflows,d",      	"Dump the flows to stdout.")
		("statistics,S",      	"Show statistics of the network stack.")
		("pstatistics,p",      	"Show statistics of the process.")
		("help,h",     		"Show help.")
		("version,v",   	"Show version string.")
		;

	mandatory_ops.add(optional_ops);

	try
	{
        	po::store(po::parse_command_line(argc, argv, mandatory_ops), var_map);

        	if (var_map.count("help"))
        	{
            		std::cout << "iaengine " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
            		return false;
        	}
        	if (var_map.count("version"))
        	{
            		std::cout << "iaengine " VERSION << std::endl;
            		return false;
        	}
		if((var_map.count("interface") == 0)&&(var_map.count("pcapfile") == 0))
		{
            		std::cout << "iaengine " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
			return false;
		}

		if (var_map.count("dumpflows")) print_flows = true;
		if (var_map.count("statistics")) show_statistics = true;
		if (var_map.count("pstatistics")) show_pstatistics = true;

        	po::notify(var_map);
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

	BasicConfigurator::configure();
	
	pktdis = PacketDispatcherPtr(new PacketDispatcher());

	if(stack_name.compare("lan") == 0)
	{
		//StackLanPtr stack_lan = StackLanPtr(new StackLan());
		//stack = stack_lan;
		stack = NetworkStackPtr(new StackLan());
	}else{
		if (stack_name.compare("mobile") ==0)
		{
			stack = NetworkStackPtr(new StackMobile());
		}else{
			std::cout << "iaengine: Unknown stack " << stack_name << std::endl;
			exit(-1);
		}
	}
	stack->setTotalTCPFlows(tcp_flows_cache);	
	stack->setTotalUDPFlows(udp_flows_cache);	

        sm = SignatureManagerPtr(new SignatureManager());

        sm->addSignature("bitorrent dht","^d1:ad2:id20");

	stack->setUDPSignatureManager(sm);

	if(var_map.count("enable-frequencies") == 1)
	{
		stack->enableFrequencyEngine(true);
		enable_frequencies = true;
	}

	// connect with the stack
        pktdis->setStack(stack);

	system_stats = SystemPtr(new System());

	if(var_map.count("pcapfile") == 1)
	{
        	pktdis->openPcapFile(pcapfile.c_str());
		try
		{
			atexit(iaengineExit);
			pktdis->runPcap();
		}
		catch(std::exception& e)
		{
			std::cerr << "Error: " << e.what() << std::endl;
		}
		pktdis->closePcapFile();
	}
	else
	{
		if(var_map.count("interface") == 1)
		{
        		pktdis->openDevice(interface.c_str());
			try
			{
				atexit(iaengineExit);
				pktdis->run();
			}
			catch(std::exception& e)
			{
				std::cerr << "Error: " << e.what() << std::endl;
			}
			pktdis->closeDevice();

		}
	}

	return 0;
}

