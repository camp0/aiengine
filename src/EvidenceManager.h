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
#ifndef SRC_EVIDENCEMANAGER_H_
#define SRC_EVIDENCEMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <iostream>
#include <boost/iostreams/device/mapped_file.hpp>
#include <pcap.h>
#include "Packet.h" 
#include "Protocol.h" // for unit converter

namespace aiengine {

typedef struct {
	int32_t t0;
	int32_t t1;
	int32_t len;
	int32_t caplen;
} pcap_header_writeable;

class EvidenceManager 
{
public:

	explicit EvidenceManager(int32_t size):
		evidence_file_(),
		filename_(),
		total_size_(size),
		total_files_(0),
		total_write_packets_(0),
		evidence_offset_(0),
		evidence_data_(nullptr)
	{}
	
	explicit EvidenceManager():EvidenceManager(default_size) {}

    	virtual ~EvidenceManager() { disable(); }

	// By default the system creates a mmap of 128 MBs
	// Depending on the use of this functionality may be a small
	// size of a bigger size is required.
	static constexpr int32_t default_size = 1024 * 1024 * 128;

	void statistics() { std::cout << *this; };	

	void enable();
	void disable();
	void write(const Packet& pkt);

	friend std::ostream& operator<< (std::ostream& out, const EvidenceManager& em);

private:
	boost::iostreams::mapped_file_sink evidence_file_;
	std::string filename_;
	int32_t total_size_;
	int32_t total_files_;
	int32_t total_write_packets_;
	int32_t evidence_offset_;
	char *evidence_data_;
};

} // namespace aiengine

#endif  // SRC_EVIDENCEMANAGER_H_
