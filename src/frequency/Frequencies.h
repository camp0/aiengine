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
#ifndef SRC_FREQUENCY_FREQUENCIES_H_
#define SRC_FREQUENCY_FREQUENCIES_H_

#include <sstream>
#include <iostream>
#include <array>
#include <unordered_map>
#include <cmath>

namespace aiengine {

class Frequencies 
{
public:
    	Frequencies():freqs_() { reset(); }
    	virtual ~Frequencies() {}

	void reset() { for (auto& value: freqs_) value = 0;}

	void addPayload(unsigned char *payload, int length) {
	
		for(int i=0;i< length;++i) ++freqs_[payload[i]];
	}

	std::string getFrequenciesString() const { 
	
		std::ostringstream os;

		os << "[";
		for (auto& value: freqs_) os << value << ","; 

		std::string foo(os.str());
		foo.pop_back();
		os.str(foo);
		os.seekp (0, os.end);  

		os << "]";
		return os.str();
	}

	friend std::ostream& operator<<(std::ostream& os, const Frequencies& fq) {
	
		std::ostringstream os_f;

		os << "Begin frequencies" << std::endl;
                os_f << "[";
                for (auto& value: fq.freqs_) os_f << value << ",";

                std::string foo(os_f.str());
                foo.pop_back();
                os_f.str(foo);
                os_f.seekp (0, os_f.end);

                os_f << "]";
		os << os_f.str() << std::endl;
	}	

	int& operator[](const int index) {
	
		return freqs_[index];
	}

	Frequencies operator+(const Frequencies& fq) {
	
		Frequencies freqs;

		for(int i = 0;i<255;++i) freqs[i] = freqs_[i] + fq.freqs_[i];
		return freqs;
	}	

	Frequencies operator+(const int& value) {
	
		Frequencies freqs;

		for(int i = 0;i<255;++i) freqs[i] = freqs_[i] + value;
		return freqs;
	}

        Frequencies operator /(const int& value) {
        
                Frequencies freqs;

                for (int i = 0;i<255;++i) freqs[i] = freqs_[i] / value;
                return freqs;
        }

        bool operator==(const Frequencies& fq) {
        
                for (int i = 0;i<255;++i)
			if (freqs_[i] != fq.freqs_[i])
				return false;	
		return true;
        }

        bool operator!=(const Frequencies& fq) {
        
                for (int i = 0;i<255;++i)
                        if (freqs_[i] != fq.freqs_[i])
                                return true;
                return false;
        }

	int getDispersion() { 
	
		std::unordered_map<int,int> values;

                for (auto& value: freqs_) values[value] = 1; 
		return values.size();
	}

	double getEnthropy() {
	
		double h = 0, x;

		for (auto& value: freqs_) {
			x = value / 255;
			if (x>0) h += - x * std::log2(x);	
		}
		return h;
	}

private:
	std::array<int,255> freqs_;
};

} // namespace aiengine

#endif  // SRC_FREQUENCY_FREQUENCIES_H_
