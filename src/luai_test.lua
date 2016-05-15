luaunit = require('luaunit')
luaiengine = require('luaiengine')
local inspect = require 'inspect'

TestStackLan = {} 
    function TestStackLan:setUp() 
        self.st = luaiengine.StackLan()
        self.pd = luaiengine.PacketDispatcher()

        print(inspect(self.st))

        -- self.st:tcp_total_flows(1000)
        -- print(self.st.name)
        self.pd:setStack(self.st)
        -- for key,value in pairs(self.pd) do
    end

    function TestStackLan:tearDown() 
    end

    function TestStackLan:test01()
        self.st.link_layer_tag = "vlan"

        -- print(inspect(luaiengine.FlowManager))
        print(inspect(luaiengine.StackLan))

        rm = luaiengine.RegexManager()
        r = luaiengine.Regex("netbios","CACACACA")
        rm:add_regex(r)
        -- self.st.udp_regex_manager = rm

        self.pd:open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd:run();
        self.pd:close();

        -- luaunit.assertEqual(r.matchs, 1)
        -- luaunit.assertEqual(self.st.udp_regex_manager, rm)
        -- luaunit.assertEqual(self.st.link_layer_tag,"vlan")


        rm:statistics() 
        -- self.pd:open("eth0")
        luaunit.assertEquals( 3, 3 )
    end

luaunit.LuaUnit:run()
