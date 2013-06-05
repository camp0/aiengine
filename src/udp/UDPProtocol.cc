#include "UDPProtocol.h"
#include <iomanip> // setw

void UDPProtocol::statistics(std::basic_ostream<char>& out)
{
	out << "UDPProtocol statistics" << std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;

}

void UDPProtocol::processPacket()
{
	// Get the ips and ports for the hash access
	/*	
        FlowCache *fc = new FlowCache();
        FlowManager *fm = new FlowManager();

        fc->createFlows(10);
        FlowPtr f1 = FlowPtr(fc->acquireFlow());
        BOOST_CHECK(f1.use_count() == 1);
        BOOST_CHECK(fm->getNumberFlows() == 0);

        unsigned long h1 = 1^2^3^4^5;
        unsigned long h2 = 4^5^3^1^2;
        unsigned long hfail = 10^10^10^10^10; // for fails
        f1->setId(h1);

        fm->addFlow(f1);
        BOOST_CHECK(fm->getNumberFlows() == 1);
        FlowPtr f2 = fm->findFlow(h1,hfail);
        BOOST_CHECK(f2.get() == f1.get());
        fm->removeFlow(f1);
	*/


} 
