#ifndef _Frequencies_H_
#define _Frequencies_H_

#include <sstream>
#include <iostream>
#include <array>
#include <unordered_map>

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

	std::string getFrequenciesString() const 
	{
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

	friend ostream& operator<<(ostream& os, const Frequencies& fq)
	{
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

	int getDispersion() 
	{
		std::unordered_map<int,int> values;

                for (auto& value: freqs_) values[value] = 1; 
		return values.size();
	}

private:
	std::array<int,255> freqs_;
};

typedef std::shared_ptr<Frequencies> FrequenciesPtr;
typedef std::weak_ptr<Frequencies> FrequenciesPtrWeak;

#endif
