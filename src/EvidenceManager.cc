/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
 *
 */
#include "EvidenceManager.h"

namespace aiengine {

void EvidenceManager::enable() {

	if (!evidence_file_.is_open()) {
		// Enable the mmap and the mmsync syscalls of the kernel
		boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
       		static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y%m%d_%H%M%S"));
        
		std::basic_stringstream<char> name;

        	name.imbue(loc);
        	name << "evidences." << getpid() << "." << now << ".pcap";

		boost::iostreams::mapped_file_params params;

		params.path = name.str();
		params.new_file_size = total_size_;
		params.offset = 0;
		params.length = 0;
		params.length = total_size_;
		evidence_file_.open(params);		

		filename_ = name.str();

		struct pcap_file_header pheader;	

		pheader.magic = 0xa1b2c3d4; // MAGIC NUMBER FOR TCPDUMP
		pheader.version_major = PCAP_VERSION_MAJOR;
		pheader.version_minor = PCAP_VERSION_MINOR;
		pheader.thiszone = 0;
		pheader.sigfigs = 0;
		pheader.snaplen = 1500;
		pheader.linktype = 1;
			
		evidence_data_ = evidence_file_.data();
		std::memcpy(evidence_data_,&pheader,sizeof(struct pcap_file_header));
		evidence_offset_ = sizeof(struct pcap_file_header);
		++ total_files_;
	}
}


void EvidenceManager::disable() {

	if (evidence_file_.is_open()) {
		evidence_file_.close();
#if defined(__LINUX__)
		// Truncate the file to the exact memory on it
		int fd = open(filename_.c_str(), O_WRONLY, 0777);
		if (fd > 0) {
			// std::cout << "Realocating file:" << filename_ << " from offset:" << evidence_offset_ << " total:" << total_size_ - evidence_offset_ << std::endl;
			int ret = fallocate(fd,FALLOC_FL_PUNCH_HOLE,evidence_offset_, total_size_ - evidence_offset_);
			// td::cout << "ret=" << ret << std::endl;perror("fallocate:");	
		}
		close(fd);
#endif
		evidence_data_ = nullptr;
		evidence_offset_ = 0;
	}
}

void EvidenceManager::write(const Packet& pkt) {
	int length = pkt.curr_packet.getLength();

	if (evidence_offset_ + length + sizeof(pcap_header_writeable) > total_size_ ) {
		disable();
		enable();
	}

	pcap_header_writeable header;

	header.t0 = 0;
	header.t1 = 0;
	header.len = length;
	header.caplen = length;

	std::memcpy(&evidence_data_[evidence_offset_],&header,sizeof(pcap_header_writeable));	
	evidence_offset_ += sizeof(pcap_header_writeable);
	std::memcpy(&evidence_data_[evidence_offset_],pkt.curr_packet.getPayload(),length);	
	evidence_offset_ += length;
	++ total_write_packets_;
}

std::ostream& operator<< (std::ostream& out, const EvidenceManager& em) {

        int alloc_memory = em.total_size_;
        std::string unit = "Bytes";

        unitConverter(alloc_memory,unit);

        out << "EvidenceManager(" << &em <<") statistics" << std::endl;
        out << "\t" << "Total file allocated:   " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
        out << "\t" << "Total write packets:    " << std::setw(10) << em.total_write_packets_ <<std::endl;
        out << "\t" << "Total files:        " << std::setw(14) << em.total_files_ <<std::endl;

	return out;
}

} // namespace aiengine
