#ifndef _ForwarderVisitor_H_
#define _ForwarderVisitor_H_

//#include <boost/weak_ptr.hpp>

class ForwarderVisitor
{
public:
	ForwarderVisitor() {}
    	virtual ~ForwarderVisitor() {}

 /*   virtual void visit(IPmsg& msg) = 0;
    virtual void visit(TCPmsg& p) = 0;
    virtual void visit(UDPmsg& p) = 0;
    virtual void visit(HTTPmsg& p) = 0;
  */
};

#endif
