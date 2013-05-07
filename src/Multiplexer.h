#ifndef _Multiplexer_H_
#define _Multiplexer_H_

#include <iostream>
#include <vector>
#include <map>

#include "Forwarder.h"
//#include "IPaccessor.h"
#include "ForwarderFactory.h"

class Multiplexer : public Forwarder
{
protected:
    Accessor& accessor_;
    ForwarderFactory& sideBfactory_;
    boost::weak_ptr<Conduit> sideA_;

    typedef std::map<ProtocolType,Conduit*> MapSideB;
    MapSideB sideBlist_;

public:
    Multiplexer(Accessor& accessor, ConduitFactory& sideBfactory) :
        accessor_(accessor),
        sideBfactory_(sideBfactory)
    {
    }
    virtual ~Multiplexer();

    virtual void setSideA(const ForwarderPtr& side); 
    virtual void setSideB(const ForwarderPtr& side);
    virtual const ForwarderPtrWeak& getSideA() const;
    virtual const ForwarderPtrWeak& getSideB() const;

    virtual const Forwarder& getSideB(ProtocolType key);

    void addSideB(ProtocolType key, Forwarder* sideB);

    virtual const ForwarderFactory& getFactory() const;
    virtual const Forwarder& getAccessor() const;
};

class UnhandledPktMux : public Muxltiplexer
{
 private:
    std::ofstream& logfile_;

 private:

 public:
    UnhandledPktMux(std::ofstream& logfile, Accessor& accessor, ConduitFactory& sideBfactory) :
    Mux(accessor, sideBfactory),
    logfile_(logfile) {}

    virtual ~UnhandledPktMux() {}

    void visit(IPmsg& msg) {}
    void visit(TCPmsg& pkt) { throw "UnhandledPktMux can not handle TCP messages"; }
    void visit(UDPmsg& p) { throw "UnhandledPktMux can not handle UDP messages"; }
    void visit(HTTPmsg& p) { throw "UnhandledPktMux can not handle HTTP messages"; }
};


#endif
