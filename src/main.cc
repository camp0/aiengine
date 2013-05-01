#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <csignal>
#include <boost/program_options.hpp>
#include <fstream>

bool process_command_line(int argc, char **argv,
	std::string &local_address,
	unsigned short &local_port,
	std::string &remote_address,
	unsigned short &remote_port,
	std::string &regex_exp,
	std::string &regex_file,
	std::string &action_str)
{
	namespace po = boost::program_options;

	po::options_description mandatory_ops("Mandatory arguments");
	mandatory_ops.add_options()
		("localip,l",   po::value<std::string>(&local_address)->required(),
			"set the local address of the proxy.")
		("localport,p",   po::value<unsigned short>(&local_port)->required(),
			"set the local port of the proxy.")
		("remoteip,r", po::value<std::string>(&remote_address)->required(), 
			"set the remote address of the database.")
		("remoteport,q", po::value<unsigned short>(&remote_port)->required(), 
			"set the remote port of the database.")
        	;

	po::options_description optional_ops("Optional arguments");
	optional_ops.add_options()
		("help",     	"show help")
		("version,v",   "show version string")
          	("regex,R", po::value<std::string>(&regex_exp), 
			"use a regex for the user queries(default action print).")
          	("regexfile,F", po::value<std::string>(&regex_file), 
			"use a regex file for the user queries(default action print).")
          	("action,a", po::value<std::string>(&action_str), 
			"sets the action when matchs the regex (print,close,reject,drop).")
		;

	mandatory_ops.add(optional_ops);

	try
	{
		po::variables_map vm;
        	po::store(po::parse_command_line(argc, argv, mandatory_ops), vm);

        	if (vm.count("help"))
        	{
            		std::cout << "FireSql " VERSION << std::endl;
            		std::cout << mandatory_ops << std::endl;
            		return false;
        	}
        	if (vm.count("version"))
        	{
            		std::cout << "FireSql " VERSION << std::endl;
            		return false;
        	}


        	po::notify(vm);
    	}
	catch(boost::program_options::required_option& e)
    	{
            	std::cout << "FireSql " VERSION << std::endl;
        	std::cerr << "Error: " << e.what() << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
    	}
    	catch(...)
    	{	
            	std::cout << "FireSql " VERSION << std::endl;
        	std::cerr << "Unsupported option." << std::endl;
		std::cout << mandatory_ops << std::endl;
        	return false;
    	}


	return true;
}

void signalHandler( int signum )
{
	exit(signum);  
}

int main(int argc, char* argv[])
{
	std::string local_host;
	std::string remote_host;
	std::string regex_exp;
	std::string regex_file;
	std::string action_str;
	unsigned short local_port;
	unsigned short remote_port;

	if(!process_command_line(argc,argv,local_host,local_port,remote_host,remote_port,
		regex_exp,regex_file,action_str))
	{
		return 1;
	}

    	signal(SIGINT, signalHandler);  

/*
   	try
   	{
		proxy = new Proxy(local_host,local_port,remote_host,remote_port);
		
		proxy->start();
		proxy->run();
   	}
   	catch(std::exception& e)
   	{
      		std::cerr << "Error: " << e.what() << std::endl;
      		return 1;
   	}
*/
	return 0;
}

