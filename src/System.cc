/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "System.h"

namespace aiengine {

void System::statistics(std::basic_ostream<char>& out) {

	struct rusage usage;

	getrusage(RUSAGE_SELF,&usage);

	end_time_ = boost::posix_time::microsec_clock::local_time();
	boost::posix_time::time_duration duration(end_time_ - start_time_);

        out << "System process statistics" << std::dec <<  std::endl;
        out << "\t" << "Elapsed time:      " << duration <<std::endl;
        out << "\t" << "Lock memory:                 " << std::setw(5) << (is_memory_lock_ ? "yes":"no") <<std::endl;
        out << "\t" << "Resident memory size:      " << std::setw(7) << usage.ru_maxrss <<std::endl;
        out << "\t" << "Shared memory size:          " << std::setw(5) << usage.ru_ixrss <<std::endl;
        out << "\t" << "Unshared data size:          " << std::setw(5) << usage.ru_idrss <<std::endl;
        out << "\t" << "Unshared stack size:         " << std::setw(5) << usage.ru_isrss <<std::endl;
        out << "\t" << "Page reclaims:             " << std::setw(7) << usage.ru_minflt <<std::endl;
        out << "\t" << "Page faults:                 " << std::setw(5) << usage.ru_majflt <<std::endl;
        out << "\t" << "Swaps:                       " << std::setw(5) << usage.ru_nswap <<std::endl;
        out << "\t" << "Block input operations: " << std::setw(10) << usage.ru_inblock <<std::endl;
        out << "\t" << "Block output operations:     " << std::setw(5) << usage.ru_oublock <<std::endl;
        out << "\t" << "IPC messages sent:           " << std::setw(5) << usage.ru_msgsnd <<std::endl;
        out << "\t" << "IPC messages received:       " << std::setw(5) << usage.ru_msgrcv <<std::endl;
        out << "\t" << "Signal received:             " << std::setw(5) << usage.ru_nsignals <<std::endl;
        out << "\t" << "Voluntary context switches:  " << std::setw(5) << usage.ru_nvcsw <<std::endl;
        out << "\t" << "Involuntary context switches:" << std::setw(5) << usage.ru_nivcsw <<std::endl;

}

std::string System::getOSName() const {
	std::ostringstream os;

        os << system_info_.sysname;
	return os.str();
}

std::string System::getNodeName() const {
	std::ostringstream os;

        os << system_info_.nodename;
	return os.str();
}

std::string System::getReleaseName() const {
	std::ostringstream os;

        os << system_info_.release;
	return os.str();
}

std::string System::getVersionName() const {
	std::ostringstream os;

        os << system_info_.version;
	return os.str();
}

std::string System::getMachineName() const {
	std::ostringstream os;

        os << system_info_.machine;
	return os.str();
}

} // namespace aiengine
