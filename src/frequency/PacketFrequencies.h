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
#ifndef _PacketFrequencies_H_
#define _PacketFrequencies_H_

#include <sstream>
#include <iostream>
#include <array>
#include <unordered_map>
#include <cmath>

namespace aiengine {

static const int MAX_PACKET_FREQUENCIES_VALUES = 5000;

class PacketFrequencies 
{
public:

    	PacketFrequencies():freqs_() { reset(); };
    	virtual ~PacketFrequencies() {};

	void reset() { length_ = 0; for(auto& value: freqs_) value = 0;};

	void addPayload(unsigned char *payload, int length)
	{
		int limit = length;

		if(length_>= MAX_PACKET_FREQUENCIES_VALUES) return;
		if(length < 0) return;

		if(length_ + length > MAX_PACKET_FREQUENCIES_VALUES)
		{
			limit = MAX_PACKET_FREQUENCIES_VALUES  - length_ ;
		}

		for(int i=0;i< limit ;++i) freqs_[length_+i] = payload[i];
		length_ += limit;
	}

	std::string getPacketFrequenciesString() const 
	{
		std::ostringstream os;

		os << "[";
		for (int i= 0 ;i <length_;++i)
			os << freqs_[i] << ","; 

		std::string foo(os.str());
		foo.pop_back();
		os.str(foo);
		os.seekp (0, os.end);  

		os << "]";
		return os.str();
	}

	friend std::ostream& operator<<(std::ostream& os, const PacketFrequencies& fq)
	{
		std::ostringstream os_f;

		os << "Begin frequencies" << std::endl;
                os_f << "[";
		for (int i= 0 ;i <fq.length_;++i)
			os << fq.freqs_[i] << ","; 

                std::string foo(os_f.str());
                foo.pop_back();
                os_f.str(foo);
                os_f.seekp (0, os_f.end);

                os_f << "]";
		os << os_f.str() << std::endl;
	}	

	int index(int index) { return freqs_[index];};

	int& operator [](const int index)
	{
		return freqs_[index];
	}

	PacketFrequencies operator +(const PacketFrequencies& fq)
	{
		PacketFrequencies freqs;

		for(int i = 0;i<MAX_PACKET_FREQUENCIES_VALUES;++i) freqs[i] = freqs_[i] + fq.freqs_[i];
		return freqs;
	}	

	PacketFrequencies operator +(const int& value)
	{
		PacketFrequencies freqs;

		for(int i = 0;i<MAX_PACKET_FREQUENCIES_VALUES;++i) freqs[i] = freqs_[i] + value;
		return freqs;
	}

        PacketFrequencies operator /(const int& value)
        {
                PacketFrequencies freqs;

                for(int i = 0;i<MAX_PACKET_FREQUENCIES_VALUES;++i) freqs[i] = freqs_[i] / value;
                return freqs;
        }

        bool operator ==(const PacketFrequencies& fq)
        {
                for(int i = 0;i<MAX_PACKET_FREQUENCIES_VALUES;++i)
			if(freqs_[i] != fq.freqs_[i])
				return false;	
		return true;
        }

        bool operator !=(const PacketFrequencies& fq)
        {
                for(int i = 0;i<MAX_PACKET_FREQUENCIES_VALUES;++i)
                        if(freqs_[i] != fq.freqs_[i])
                                return true;
                return false;
        }

	int getDispersion() 
	{
		std::unordered_map<int,int> values;

                for (auto& value: freqs_) values[value] = 1; 
		return values.size();
	}

	double getEnthropy()
	{
		double h = 0, x;

		for(auto& value: freqs_)
		{
			x = value / 255;
			if(x>0)
				h += - x * log2(x);	
		}
		return h;
	}

	int getLength() const { return length_;};

private:
	std::array<int,MAX_PACKET_FREQUENCIES_VALUES> freqs_;
	int length_;
};

} // namespace aiengine

#endif
