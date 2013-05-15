#ifndef _Multiplexer_H_
#define _Multiplexer_H_

#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#include <map>

class Multiplexer;
typedef boost::shared_ptr<Multiplexer> MultiplexerPtr; 
typedef boost::weak_ptr<Multiplexer> MultiplexerPtrWeak; 

class Multiplexer 
{
public:
    	Multiplexer(): offset_(0) {};
    	virtual ~Multiplexer() {};

    	void virtual addUpMultiplexer(MultiplexerPtrWeak mux, int key)
	{
		muxUpMap_[key] = mux;
	}

	void virtual addDownMultiplexer(MultiplexerPtrWeak mux)
	{
		muxDown_ = mux;
	}

	MultiplexerPtrWeak getDownMultiplexer() const { return muxDown_;}
	MultiplexerPtrWeak getUpMultiplexer(int key) const
	{
		MuxMap::const_iterator it = muxUpMap_.find(key);
		MultiplexerPtrWeak mp;

		if(it != muxUpMap_.end())
		{
			mp = it->second;
		} 
		return mp;
	} 

	int getNumberUpMultiplexers() const { return muxUpMap_.size(); }
	
private:
	MultiplexerPtrWeak muxDown_;
	int offset_;
    	typedef std::map<int,MultiplexerPtrWeak> MuxMap;
	MuxMap muxUpMap_;
};


#endif
