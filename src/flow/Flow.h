#ifndef _Flow_H
#define _Flow_H

class Flow {
public:
    	Flow() {reset();};
    	virtual ~Flow(){};

	void setId(unsigned long hash) { hash_=hash;};
	unsigned long getId() const { return hash_;};

	int32_t total_bytes;
	int32_t total_packets;
	
	void reset()
	{
		hash_ = 0;
		total_bytes = 0;
		total_packets = 0;
	};
private:
	unsigned long hash_;
};

typedef std::shared_ptr<Flow> FlowPtr;
typedef std::weak_ptr<Flow> FlowPtrWeak;

#endif
