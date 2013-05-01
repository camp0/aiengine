#include "FlowManager.h"


FlowManager::FlowManager(std::ofstream& logfile) :
	logfile_(logfile),
    	debug_(false)
{
}

FlowManager::~FlowManager()
{
	flowMap_.clear();
    	timers_.clear();
}

void FlowManager::setTimeStamp(timeval now)
{
	now_ = now;
    	timeout(now);
}

void FlowManager::inactivateAllFlows()
{
	FlowMap::iterator posStart = flowMap_.begin();
    	FlowMap::iterator posEnd = flowMap_.end();
    	FlowMap::iterator posTmp;

    	while (posStart != posEnd) {
        	flow* f = posStart->second;
        	f->comatose = 1;

        	flowMap_.erase(posStart++);

        	if (f->proto == IPPROTO_TCP) {
            		comotoseTCPflows_.push_back(f);
        	}else {
            		comotoseUDPflows_.push_back(f);
        	}

        	// get a view to index #1
        	flow_container::nth_index<1>::type& sorted_index = timers_.get<1>();

        	// use sorted_index as a regular std::set
        	sorted_index.erase(f);

		/*
		std::list<connection*>::iterator it = std::find(timers_.begin(), timers_.end(), conn);
		if (it != timers_.end()) {
		    timers_.erase(it);
		}
       		*/
    	}
}


bool FlowManager::inactivateFlow(flow* f, bool removeTimer)
{
    	unsigned long h = (f->id.saddr ^ f->id.daddr ^ f->id.sport ^ f->id.dport ^ f->id.protocol);
    	std::pair<FlowMap::iterator, FlowMap::iterator> p = flowMap_.equal_range(h);

    	for (FlowMap::iterator i = p.first; i != p.second; i++) {
        	if ((*i).second->id.saddr == f->sid.saddr &&
		    (*i).second->id.daddr == f->sid.daddr &&
		    (*i).second->id.sport == f->sid.sport &&
		    (*i).second->id.dport == f->sid.dport &&
		    (*i).second->id.protocol == f->sid.protocol) {

		    if (debug_) {
			in_addr a; a.s_addr=f->id.saddr; std::string src(inet_ntoa(a));
			in_addr b; b.s_addr=f->id.daddr; std::string dst(inet_ntoa(b));
			logfile_ << "FlowManager::inactiveFlow, Remove connection from active map " << flowMap_.size() << " "
				 << ((f->proto == IPPROTO_TCP) ? "(TCP)" : "(UDP)" )
				 << ": ip.src == " << src
                         << " && ip.dst == " << dst << std::endl;
            	}

            	flowMap_.erase(i);

            	f->comatose = 1;

		if (conn->proto == IPPROTO_TCP) {
			comotoseTCPconnections_.push_back(f);
		}else {
			comotoseUDPconnections_.push_back(f);
            	}

            	if (removeTimer) {
        		// get a view to index #1
        		flow_container::nth_index<1>::type& sorted_index = timers_.get<1>();

        		// use sorted_index as a regular std::set
        		sorted_index.erase(f);

/*
                // remove from timer list
                //timers_.erase(conn->rittimer);
                //timers_.remove(conn);

                std::list<connection*>::iterator it = std::find(timers_.begin(), timers_.end(), conn);
                if (it != timers_.end()) {
                    timers_.erase(it);
                }
*/
            }

            return true;
        }
    }
    return false;
}

void FlowManager::timeout(const timeval& now)
{
    while (!timers_.empty()) {
        connection* conn = timers_.front();

        if((conn->creation_time.tv_sec + FlowManager::inactivityTime_) > now.tv_sec) {
            // there is no additional flow to timeout
            break;
        }

        timers_.pop_front();

        if((now.tv_sec - conn->last_datagram.tv_sec) < FlowManager::inactivityTime_) {
            timers_.push_back(conn);
            conn->creation_time = now;
        }
        else {
            if (debug_) {
                in_addr a; a.s_addr=conn->sid.saddr; std::string src(inet_ntoa(a));
                in_addr b; b.s_addr=conn->sid.daddr; std::string dst(inet_ntoa(b));
                logfile_ << "FlowManager::timeout, inactivity timeout "
                         << now.tv_sec-conn->last_datagram.tv_sec
                         << " sec : ip.src == " << src
                        << " && ip.dst == " << dst << std::endl;
            }

            inactivateFlow(conn, false);
        }
    }
}

connection* FlowManager::findFlow(unsigned long hash, const streamid& sid)
{
    std::pair<FlowMap::const_iterator, FlowMap::const_iterator> p = connMap_.equal_range(hash);
    for (FlowMap::const_iterator i = p.first; i != p.second; i++) {
        if ((*i).second->sid.saddr == sid.saddr &&
            (*i).second->sid.daddr == sid.daddr &&
            (*i).second->sid.sport == sid.sport &&
            (*i).second->sid.dport == sid.dport &&
            (*i).second->sid.protocol == sid.protocol) {

            return (*i).second;
        }
    }
    return NULL;
}

bool FlowManager::insertFlow(unsigned long hash, connection* conn)
{
    if (connMap_.insert(value_type(hash, conn)) != connMap_.end()) {
        if (debug_) {
            in_addr a; a.s_addr=conn->sid.saddr; std::string src(inet_ntoa(a));
            in_addr b; b.s_addr=conn->sid.daddr; std::string dst(inet_ntoa(b));
            logfile_ << "FlowManager::insertFlow: Added connection to map: "
                     << " ip.src == " << src
                     << " && ip.dst == " << dst << std::endl;
        }

        // add flow to the end of the timer queue
        timers_.push_back(conn);

        return true;
    }
    return false;
}

