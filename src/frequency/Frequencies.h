#ifndef _Frequencies_H_
#define _Frequencies_H_

#include <iostream>
#include <array>
using namespace std;

class Frequencies 
{
public:
    	Frequencies():freqs_() { reset(); };
    	virtual ~Frequencies() {};

	void reset() { for(auto& value: freqs_) value = 0;};

	void addPayload(unsigned char *payload, int length)
	{
		for(int i=0;i< length;++i) ++freqs_[payload[i]];
	}

	friend ostream& operator<<(ostream& os, const Frequencies& fq)
	{
		os << "Begin frequencies(" << &fq << ")" << std::endl;
		for (auto& value: fq.freqs_)
			os << hex << (int)value << " ";
		os << std::endl; 
	}	

	int& operator [](const int index)
	{
		return freqs_[index];
	}

	Frequencies operator +(const Frequencies& fq)
	{
		Frequencies freqs;

		for(int i = 0;i<255;++i) freqs[i] = freqs_[i] + fq.freqs_[i];
		return freqs;
	}	

	Frequencies operator +(const int& value)
	{
		Frequencies freqs;

		for(int i = 0;i<255;++i) freqs[i] = freqs_[i] + value;
		return freqs;
	}

        Frequencies operator /(const int& value)
        {
                Frequencies freqs;

                for(int i = 0;i<255;++i) freqs[i] = freqs_[i] / value;
                return freqs;
        }

        bool operator ==(const Frequencies& fq)
        {
                for(int i = 0;i<255;++i)
			if(freqs_[i] != fq.freqs_[i])
				return false;	
		return true;
        }

        bool operator !=(const Frequencies& fq)
        {
                for(int i = 0;i<255;++i)
                        if(freqs_[i] != fq.freqs_[i])
                                return true;
                return false;
        }


private:
	std::array<int,255> freqs_;
};

typedef std::shared_ptr<Frequencies> FrequenciesPtr;
typedef std::weak_ptr<Frequencies> FrequenciesPtrWeak;

#endif
