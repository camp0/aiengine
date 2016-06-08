#!/usr/bin/env lua

-- Example for use DatabaseAdaptor for drop information 

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

luaiengine = require('luaiengine')

FileAdaptor = {}

FileAdaptor.new = function(self,filename)
    local self = {}
    setmetatable(self,luaiengine.DatabaseAdaptor)
    self.f = assert(io.open(filename, "w"))

    self.insert = function(key)
    end
    self.update = function(key,data)
        self.f:write(data.."\n")
    end
    self.remove = function(key)
    end
    return self
end


-- Load an instance of a Network Stack Lan 
st = luaiengine.StackLan()
pd = luaiengine.PacketDispatcher()

st.tcp_flows = 327680
st.udp_flows = 163840

pd:set_stack(st)

adap = FileAdaptor:new("tcpflows.dat")
st:set_udp_database_adaptor("adap")

pd:open("enp0s25") 
pd:run()
pd:close()

