#ifndef _Protocol_H_
#define _Protocol_H_

class Protocol 
{
public:
    	Protocol(){};
    	virtual ~Protocol() {};

	void virtual setMultiplexer(MultiplexerPtrWeak mux)
	{
		mux_ = mux;
	}

	MultiplexerPtrWeak virtual getMultiplexer() const { return mux_;}; 

private:
	MultiplexerPtrWeak mux_;
};

#endif
