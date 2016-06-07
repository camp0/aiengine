#!/usr/bin/env lua

-- Example for detect denial of service attacks  

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"


luaiengine = require('luaiengine')

function scheduler_handler_tcp()

    print("TCP DoS Checker")
    c = st:get_counters("TCPProtocol")
    -- Code the intelligence for detect DDoS based on 
    -- combination flags, bytes, packets and so on. 
    syns = c:get("syns")
    synacks = c:get("synacks")
    print(syns,synacks)
end

function scheduler_handler_ntp()

    print("NTP DDoS Checker")
    c = st:get_counters("NTPProtocol")
end
 

-- Load an instance of a Network Stack Lan 
st = luaiengine.StackLan()
pd = luaiengine.PacketDispatcher()

st.tcp_flows = 327680
st.udp_flows = 163840

-- Sets a handler method that will be call
-- every 5 seconds for check the values
pd:set_scheduler("scheduler_handler_tcp",5)
pd:set_stack(st)
pd:open("enp0s25") 
pd:run()
pd:close()

