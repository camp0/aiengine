luaunit = require('luaunit')
luaiengine = require('luaiengine')
local inspect = require 'inspect'

TestStackLan = {} 
    function TestStackLan:setUp() 
        self.st = luaiengine.StackLan()
        self.pd = luaiengine.PacketDispatcher()

        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        -- self.st:tcp_total_flows(1000)
        -- print(self.st.name)
        self.pd:setStack(self.st)
    end

    function TestStackLan:tearDown() 
    end

    function TestStackLan:test01()
        self.st.link_layer_tag = "vlan"

        -- print(inspect(luaiengine.Regex))
        -- print(inspect(luaiengine.StackLan))

        rm = luaiengine.RegexManager()
        r = luaiengine.Regex("netbios","CACACACA")

        rm:add_regex(r)

        self.st.udp_regex_manager = rm

        self.pd:open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd:run();
        self.pd:close();

        luaunit.assertEquals( r.matchs, 1 )
        -- TODO: luaunit.assertEquals( self.st.udp_regex_manager, rm)
    end

    function TestStackLan:test02()
        local callme = false
        -- print(inspect(luaiengine.SSLInfo))

        function mycallback (flow)
            luaunit.assertEquals( flow.src_ip, "192.168.1.13")
            luaunit.assertEquals( flow.dst_ip, "74.125.24.189")
            luaunit.assertNotEquals( flow.ssl_info, nill)
            luaunit.assertEquals( flow.http_info, nill)
            luaunit.assertEquals( flow.dns_info, nill)
            luaunit.assertEquals( flow.smtp_info, nill)

            luaunit.assertEquals( flow.ssl_info.server_name, "0.drive.google.com")
            callme = true
        end

        function mycallback2 () 
        end
        d = luaiengine.DomainName("Google Drive Cert",".drive.google.com")

        -- print(inspect(luaiengine.DomainNameManager))

        d:setCallback("mycallback")
        dm = luaiengine.DomainNameManager()
        dm:add_domain_name(d)

        self.st:set_domain_name_manager(dm,"SSLProtocol")

        self.pd:open("../pcapfiles/sslflow.pcap");
        self.pd:run();
        self.pd:close();

        -- print(inspect(luaiengine.DomainName))
        luaunit.assertEquals(d.matchs , 1)
        luaunit.assertEquals( callme, true)
    end
   
    function TestStackLan:test03()
        -- Verify SSL traffic with domain callback and IPset
        local callme_set = false
        local callme_domain = false

        function ipset_callback(flow)
            callme_set = true
        end 

        function domain_callback(flow)
            callme_domain = true
        end

        ip = luaiengine.IPSet("Specific IP address")
        ip:add_ip_address("74.125.24.189")
        ip:setCallback("ipset_callback")

        ipm = luaiengine.IPSetManager()
        ipm:add_ip_set(ip)

        d = luaiengine.DomainName("Google All",".google.com")
        d:setCallback("domain_callback")

        dm = luaiengine.DomainNameManager()
        dm:add_domain_name(d)

        self.st.tcp_ip_set_manager = ipm
        self.st:set_domain_name_manager(dm,"SSLProtocol")

        self.pd:open("../pcapfiles/sslflow.pcap")
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals(d.matchs , 1)
        luaunit.assertEquals( callme_set, true)
        luaunit.assertEquals( callme_domain, true)
    end

TestStackMobile = {} 
    function TestStackMobile:setUp() 
        self.st = luaiengine.StackMobile()
        self.pd = luaiengine.PacketDispatcher()

        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        --self.pd:setStack(self.st)
    end

    function TestStackMobile:tearDown() 
    end

    function TestStackMobile:test01()
        -- self.st.link_layer_tag = "vlan"

        -- print(inspect(luaiengine.StackMobile))

    end

TestStackLanIPv6 = {} 
    function TestStackLanIPv6:setUp() 
        self.st = luaiengine.StackLanIPv6()
        self.pd = luaiengine.PacketDispatcher()

        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.pd:setStack(self.st)
    end

    function TestStackLanIPv6:tearDown() 
    end

    function TestStackLanIPv6:test01()

        rm = luaiengine.RegexManager()
        r = luaiengine.Regex("generic exploit","\x90\x90\x90\x90\x90\x90\x90")
        rm:add_regex(r)

        self.st.tcp_regex_manager = rm

        self.pd:open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals(r.matchs, 1)
    end

    function TestStackLanIPv6:test02()

        im = luaiengine.IPSetManager()

        -- print(inspect(luaiengine.IPSetManager))
        -- print(inspect(luaiengine.IPSet))

        i = luaiengine.IPSet("IPv6 generic set")
        i:add_ip_address("dc20:c7f:2012:11::2")
        i:add_ip_address("dc20:c7f:2012:11::1")
        -- ipset.callback = ipset_callback

        im:add_ip_set(i)

        self.st.tcp_ip_set_manager = im

        self.pd:open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd:run()
        self.pd:close()

        luaunit.assertEquals(i.total_lookups_in, 1)
        luaunit.assertEquals(i.total_lookups_out, 0)
        -- im:statistics()
    end

luaunit.LuaUnit:run()
