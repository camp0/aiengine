#ifndef _Multiplexer_H_
#define _Multiplexer_H_

#include <iostream>
#include <vector>
#include <map>

#include "Forwarder.h"
//#include "IPaccessor.h"
#include "ForwarderFactory.h"

class Mux : public Conduit
{
 protected:
    Accessor& accessor_;
    ConduitFactory& sideBfactory_;
    boost::weak_ptr<Conduit> sideA_;

    typedef std::map<ProtocolType,Conduit*> MapSideB;
    MapSideB sideBlist_;

 public:
    virtual ~Mux()
    {
        MapSideB::iterator iter = sideBlist_.begin();
        for( ; iter != sideBlist_.end(); iter++) {
            delete (*iter).second;
        }
        sideBlist_.clear();
    }

    Mux(Accessor& accessor, ConduitFactory& sideBfactory) :
        accessor_(accessor),
        sideBfactory_(sideBfactory)
    {
    }

    virtual void setSideA(const boost::shared_ptr<Conduit>& side) { sideA_ = side; }
    virtual void setSideB(const boost::shared_ptr<Conduit>& side) { throw "Mux has multiple side B"; }
    virtual const boost::weak_ptr<Conduit>& getSideA() const { return sideA_; }
    virtual const boost::weak_ptr<Conduit>& getSideB() const
    {
        throw "Mux has multiple side B";
        return sideA_; // to prevent compile errors
    }

    virtual const Conduit& getSideB(ProtocolType key)
    {
        MapSideB::iterator it = sideBlist_.find(key);
        return *(it->second);
    }

    // we take ownership of the pointer
    void addSideB(ProtocolType key, Conduit* sideB) {
        if (sideB) {
            sideBlist_[key] = sideB;
        }
    }

    virtual const ConduitFactory& getFactory() const { return sideBfactory_; }
    virtual const Conduit& getAccessor() const { return accessor_; }
};

class UnhandledPktMux : public Mux
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
