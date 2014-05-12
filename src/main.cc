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

#include <fstream>
#include <iostream>
#include <functional>
#include <csignal>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"
#endif
#include "PacketDispatcher.h"
#include "./frequency/FrequencyGroup.h"
#include "./learner/LearnerEngine.h"
#include "System.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include <boost/date_time/posix_time/posix_time_io.hpp>

using namespace aiengine;

#ifdef HAVE_LIBLOG4CXX
using namespace log4cxx;
using namespace log4cxx::helpers;
#endif

aiengine::SystemPtr system_stats;
aiengine::PacketDispatcherPtr pktdis;
aiengine::NetworkStackPtr stack;
aiengine::RegexManagerPtr sm;
aiengine::FrequencyGroup<std::string> group;
aiengine::LearnerEngine learner;

std::map<std::string,std::function <void(FlowManagerPtr)>> group_map_options;

/* Factory of NetworkStacks implemented with lambdas */
std::map<std::string, std::function<aiengine::NetworkStackPtr()>> stack_factory {
	{ "lan",	[](){return aiengine::NetworkStackPtr(new aiengine::StackLan());}},
	{ "mobile",	[](){return aiengine::NetworkStackPtr(new aiengine::StackMobile());}},
	{ "lan6",	[](){return aiengine::NetworkStackPtr(new aiengine::StackLanIPv6());}}
};

std::string option_link_type_tag;
std::string option_learner_key;
std::string option_stack_name;
std::string option_pcapfile;
std::string option_interface;
std::string option_freqs_group_value;
std::string option_freqs_type_flows;
std::string option_regex_type_flows;
std::string option_regex;
bool option_show_flows = false;
bool option_enable_frequencies = false;
bool option_enable_regex = false;
bool option_enable_learner = false;
bool option_show_pstatistics = false;
int tcp_flows_cache;
int udp_flows_cache;
int option_statistics_level = 0;

void signalHandler( int signum ){

        exit(signum);
}

void signalHandlerShowStackStatistics( int signum) {

        boost::posix_time::ptime nowt = boost::posix_time::second_clock::local_time();
	boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
	static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y%m%d_%H%M%S"));
	std::basic_stringstream<char> ss;
	
	ss.imbue(loc);
	ss << "statistics.stack." << now << ".dat"; 

	std::ofstream outfile(ss.str());

        std::cout << "[" << nowt << "] ";
	std::cout << "Dumping stack information into " << ss.str() << std::endl;
	if (stack) 
	        if (option_statistics_level > 0)
                	stack->statistics(outfile);

	outfile.close();
}


void signalHandlerShowFlowsStatistics( int signum) {

        boost::posix_time::ptime nowt = boost::posix_time::second_clock::local_time();
        boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
        static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y%m%d_%H%M%S"));
        std::basic_stringstream<char> ss;

        ss.imbue(loc);
        ss << "flows.stack." << now << ".dat";

        std::ofstream outfile(ss.str());

        std::cout << "[" << nowt << "] ";
        std::cout << "Dumping flows information into " << ss.str() << std::endl;
        if (stack )
		stack->printFlows(outfile);

        outfile.close();
}

void configureFrequencyGroupOptions() { 

	// TODO
}


bool computeFrequencyGroup () {

	bool computed = false;
        FlowManagerPtr flow_t;

        if(option_freqs_type_flows.compare("tcp")==0) flow_t = stack->getTCPFlowManager().lock();
        if(option_freqs_type_flows.compare("udp")==0) flow_t = stack->getUDPFlowManager().lock();

        if (!flow_t) return computed;

	group.reset();

        if (option_freqs_group_value.compare("src-port") == 0) {
                group.setName("by source port");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsBySourcePort(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("dst-port") == 0) {
                group.setName("by destination port");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsByDestinationPort(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("src-ip") == 0) {
                group.setName("by source IP");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsBySourceAddress(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("dst-ip") == 0) {
                group.setName("by destination IP");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsByDestinationAddress(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("src-ip,src-port") == 0) {
                group.setName("by source IP and port");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsBySourceAddressAndPort(flow_t);
              	computed = true; 
        }
        if (option_freqs_group_value.compare("dst-ip,dst-port") == 0) {
                group.setName("by destination IP and port");
                std::cout << "Agregating frequencies " << group.getName() << std::endl;
                group.agregateFlowsByDestinationAddressAndPort(flow_t);
              	computed = true; 
        }

	if (computed) {
                std::cout << "Computing "<< group.getTotalProcessFlows() << " frequencies " << group.getName() << std::endl;
                group.compute();
	}

	return computed;
}

void showFrequencyResults() {

	if (computeFrequencyGroup()) {
		std::cout << group;
	} else {
		std::cout << "Can not compute the frequencies" << std::endl;
	}
}

void showLearnerResults() {

	std::vector<WeakPointer<Flow>> flow_list;

	flow_list = group.getReferenceFlowsByKey(option_learner_key);
	if (flow_list.size()>0) {
		learner.reset();
		std::cout << "Agregating "<< flow_list.size() << " to the LearnerEngine" << std::endl;
		learner.agregateFlows(flow_list);
		learner.compute();
		std::cout << "Regular expression generated with key:" << option_learner_key << std::endl;
		std::cout << "Regex:" << learner.getRegularExpression() <<std::endl;
		std::cout << "Ascii buffer:" << learner.getAsciiExpression() << std::endl;	
	}
}

void learnerCallback() {

	if( computeFrequencyGroup()) {
		showLearnerResults();
	}
}

void showStackStatistics(std::basic_ostream<char>& out) {

	if (option_statistics_level > 0) 
		stack->statistics(out);
}


void aiengineExit() {

	if (stack) {
		pktdis->stop();

		showStackStatistics(std::cout);

		if (option_show_flows)
              		stack->printFlows();

		if (option_enable_frequencies) {
			showFrequencyResults();
			if (option_enable_learner)
				showLearnerResults();
		}

		if (option_show_pstatistics)	
			if (system_stats)	
				system_stats->statistics();
       	}
	std::cout << "Exiting process" << std::endl;
}


int main(int argc, char* argv[]) {

	namespace po = boost::program_options;
	po::variables_map var_map;

	po::options_description mandatory_ops("Mandatory arguments");
	mandatory_ops.add_options()
		("interface,I",   po::value<std::string>(&option_interface),
			"Sets the network interface.")
		("pcapfile,P",   po::value<std::string>(&option_pcapfile),
			"Sets the pcap file or directory with pcap files.")
        	;

        po::options_description optional_ops_tag("Link Layer optional arguments");
        optional_ops_tag.add_options()
                ("tag,q",    po::value<std::string>(&option_link_type_tag)->default_value(""),
                        "Selects the tag type of the ethernet layer (vlan,mpls).")
                ;

	po::options_description optional_ops_tcp("TCP optional arguments");
	optional_ops_tcp.add_options()
		("tcp-flows,t",    po::value<int>(&tcp_flows_cache)->default_value(1024),
		  	"Sets the number of TCP flows on the pool.")
		;
	
	po::options_description optional_ops_udp("UDP optional arguments");
	optional_ops_udp.add_options()
		("udp-flows,u",    	po::value<int>(&udp_flows_cache)->default_value(512),
		  			"Sets the number of UDP flows on the pool.")
		;

	po::options_description optional_ops_sigs("Regex optional arguments");
	optional_ops_sigs.add_options()
                ("enable-regex,R", 	"Enables the Regex engine.") 
		("regex,r",    		po::value<std::string>(&option_regex)->default_value(".*"),
		  			"Sets the regex for evaluate agains the flows.")
                ("flow-class,c",  	po::value<std::string>(&option_regex_type_flows)->default_value("all"),
					"Uses tcp, udp or all for matches the signature on the flows.") 
		;

        po::options_description optional_ops_freq("Frequencies optional arguments");
        optional_ops_freq.add_options()
                ("enable-frequencies,F",  	"Enables the Frequency engine.") 
                ("group-by,g",  	po::value<std::string>(&option_freqs_group_value)->default_value("dst-port"),
					"Groups frequencies by src-ip,dst-ip,src-port and dst-port.") 
                ("flow-type,f",  	po::value<std::string>(&option_freqs_type_flows)->default_value("tcp"),
					"Uses tcp or udp flows.") 
                ("enable-learner,L",  	"Enables the Learner engine.") 
                ("key-learner,k",  	po::value<std::string>(&option_learner_key)->default_value("80"),
					"Sets the key for the Learner engine.") 
                ;

	mandatory_ops.add(optional_ops_tag);
	mandatory_ops.add(optional_ops_tcp);
	mandatory_ops.add(optional_ops_udp);
	mandatory_ops.add(optional_ops_sigs);
	mandatory_ops.add(optional_ops_freq);

	po::options_description optional_ops("Optional arguments");
	optional_ops.add_options()
		("stack,n",		po::value<std::string>(&option_stack_name)->default_value("lan"),
				      	"Sets the network stack (lan,mobile,lan6).")
		("dumpflows,d",      	"Dump the flows to stdout.")
		("statistics,s",	po::value<int>(&option_statistics_level)->default_value(0),
					"Show statistics of the network stack (5 leves).")
		("pstatistics,p",      	"Show statistics of the process.")
		("help,h",     		"Show help.")
		("version,v",   	"Show version string.")
		;

	mandatory_ops.add(optional_ops);

	try {
	
        	po::store(po::parse_command_line(argc, argv, mandatory_ops), var_map);

        	if (var_map.count("help")) {
            		std::cout << PACKAGE " " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
			std::cout << "Please report bugs to <" << PACKAGE_BUGREPORT << ">" << std::endl;
			std::cout << "Copyright (C) 2009-2014 Luis Campo Giralte <" PACKAGE_BUGREPORT <<">" << std::endl;
			std::cout << "License: GNU GPL version 2" << std::endl;
			std::cout << "This is free software: you are free to change and redistribute it." << std::endl;
			std::cout << "There is NO WARRANTY, to the extent permitted by law." << std::endl;
            		return false;
        	}
        	if (var_map.count("version")) {
            		std::cout << PACKAGE " " VERSION << std::endl;
            		return false;
        	}
		if ((var_map.count("interface") == 0)&&(var_map.count("pcapfile") == 0)) {
            		std::cout << PACKAGE " " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
			return false;
		}

		if (var_map.count("dumpflows")) option_show_flows = true;
		if (var_map.count("pstatistics")) option_show_pstatistics = true;
		if (var_map.count("enable-learner")) option_enable_learner = true;

        	po::notify(var_map);
    	
	} catch(boost::program_options::required_option& e) {
            	std::cout << PACKAGE " " VERSION << std::endl;
        	std::cerr << "Error: " << e.what() << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
	} catch(std::exception& e) {
            	std::cout << PACKAGE " " VERSION << std::endl;
        	std::cerr << "Unsupported option." << e.what() << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
    	}

    	signal(SIGINT, signalHandler);  
    	signal(SIGUSR1, signalHandlerShowStackStatistics);  
    	signal(SIGUSR2, signalHandlerShowFlowsStatistics);  

        system_stats = SystemPtr(new System());

        // Some cool banners
        std::cout << "AIEngine running on " << system_stats->getOSName();
        std::cout << " kernel " << system_stats->getReleaseName();
        std::cout << " " << system_stats->getVersionName();
        std::cout << " " << system_stats->getMachineName();
        std::cout << std::endl;

#ifdef HAVE_LIBLOG4CXX
	BasicConfigurator::configure();
#endif	
	system_stats->lockMemory();
	
	pktdis = PacketDispatcherPtr(new PacketDispatcher());

	try {
		stack = stack_factory[option_stack_name]();
	} catch (std::bad_function_call& e) {
		std::cout << PACKAGE ": Unknown stack " << option_stack_name << std::endl;
		exit(-1);
	}
	
	stack->setStatisticsLevel(option_statistics_level);

	stack->setTotalTCPFlows(tcp_flows_cache);	
	stack->setTotalUDPFlows(udp_flows_cache);	

	// Check if AIEngine is gonna work as signature extractor or as a regular packet inspector
	if (var_map.count("enable-regex") == 1) {
        	sm = RegexManagerPtr(new RegexManager());
        	sm->addRegex("experimental",option_regex);
		if (option_regex_type_flows.compare("all") == 0) {
			stack->setUDPRegexManager(sm);
			stack->setTCPRegexManager(sm);
		} else {
			if(option_regex_type_flows.compare("tcp") == 0) stack->setTCPRegexManager(sm);
			if(option_regex_type_flows.compare("udp") == 0) stack->setUDPRegexManager(sm);
		}
		stack->enableNIDSEngine(true);
		option_enable_regex = true;
	}

	if ((var_map.count("enable-frequencies") == 1)&&(option_enable_regex == false)) {
		stack->enableFrequencyEngine(true);
		option_enable_frequencies = true;
	}

	if(option_link_type_tag.length() > 0)
		stack->enableLinkLayerTagging(option_link_type_tag);	

	// connect with the stack
        pktdis->setStack(stack);

	atexit(aiengineExit);

	if(var_map.count("pcapfile") == 1)
	{
		std::vector<std::string> files;
		namespace fs = boost::filesystem;

		if (fs::is_directory(option_pcapfile.c_str())) {
			fs::recursive_directory_iterator it(option_pcapfile.c_str());
    			fs::recursive_directory_iterator endit;
    
			while (it != endit) {
      				if (fs::is_regular_file(*it)and((it->path().extension() == ".pcap")
					or(it->path().extension() == ".cap") 
					or(it->path().extension() == ".pcapng"))) {
					std::ostringstream os;
					
					os << option_pcapfile.c_str() << "/" << it->path().filename().c_str();
      					files.push_back(os.str());
				}
				++it;
			}
			sort(files.begin(),files.end());
		} else {
			files.push_back (option_pcapfile.c_str());
		}

		for (auto& entry: files) {

        		pktdis->open(entry);
			try {
				pktdis->run();
			
			}catch(std::exception& e) {
				std::cerr << "Error: " << e.what() << std::endl;
			}
			pktdis->close();
		}
	} else {
		if (var_map.count("interface") == 1) {

			if (option_enable_frequencies) // Sets the callback for learn.
				pktdis->setIdleFunction(std::bind(learnerCallback));
			
        		pktdis->open(option_interface.c_str());
			try {
				pktdis->run();
			} catch(std::exception& e) {
				std::cerr << "Error: " << e.what() << std::endl;
			}
			pktdis->close();
		}
	}
	return 0;
}

